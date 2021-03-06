from functools import partial
from io import BytesIO
from sqlalchemy import select, and_, exc
from sqlalchemy.orm.session import Session
from threading import Event, Thread
from typing import Dict, Optional, Any, Callable, overload
from unicornbottle.database import database_connect, InvalidSchemaException
from unicornbottle.models import DatabaseWriteItem, RequestResponse, ExceptionSerializer, EndpointMetadata
from unicornbottle.models import Request, Response
from unicornbottle.rabbitmq import rabbitmq_connect
import logging
import mitmproxy
import pika
import queue
import threading
import time
import traceback
import uuid

logger = logging.getLogger(__name__)
SKIP_DB_WRITE = "b179a4aa-5a42-4e04-90b6-f217eb46538b"

class RetriableException(Exception):
    """
    Exceptions which will trigger a retry on `send_retry()`
    """
    pass

class TimeoutException(RetriableException):
    """
    The RPC client has exceeded REQUEST_TIMEOUT while retrieving a response.
    """
    pass

class UnableToProxyException(RetriableException):
    """
    Raised when the response was not abled to be proxied, due to for example
    the host being unreachable or such other nonsense.
    """
    pass

class NotConnectedException(Exception):
    """
    There are shenanigans afoot. Please retry.
    """
    pass

class UnauthorizedException(Exception):
    """
    We're pretending to be secure by throwing an Unauthorized exception.
    """
    pass

class HTTPProxyClient(object):
    """
    This function implements the RPC model in a thread-safe way.
    """

    # Maximum time that we will wait for a `send_request` call.
    REQUEST_TIMEOUT = 10

    # Maximum amount of items that will be fetched from the queue prior to
    # writing.
    MAX_BULK_WRITE = 100

    # Header used for indicating the name of the target GUID in requests sent
    # to the proxy.
    UB_GUID_HEADER = 'X-UB-GUID'

    # Maximum request_responses to store per EndpointMetadata.
    MAX_REQ_RESPS = 120

    def __init__(self, is_fuzzer:bool=False) -> None:
        """
        Main constructor. `threads_start()` should normally be called by the
        instantiator immediately after construction.

        Args:
            is_fuzzer: set to True when this class is instantiated by the
                crawler. This results in the RequestResponse.sent_by_fuzzer flag
                being set in the DB. Additionally new EndpointMetadata won't be
                created if it doesn't exist already in order to prevent polluting
                the database with garbage.
        """
        self.lock = threading.Lock()
        self.threads : Dict[Callable, threading.Thread] = {}
        self.shutting_down : bool = False

        self.rabbit_connection : Optional[pika.BlockingConnection] = None
        self.channel : Optional[pika.adapters.blocking_connection.BlockingChannel] = None
        self.corr_ids : Dict[str, bool] = {}
        self.responses : Dict[str, bytes] = {}
        
        self.db_write_queue : queue.SimpleQueue = queue.SimpleQueue()
        self.is_fuzzer = is_fuzzer

        # These variables prevent race conditions on first startup.
        self.rabbit_first_start = False
        self.postgresql_first_start = False

    def threads_start(self) -> None:
        """
        Spawn the required threads and store them in self.threads.

        - RabbitMQ connection thread.
        - PostgreSQL writer thread.

        If the thread is already present in that dictionary, we check whether
        it's alive and if not we restart it. 

        This function is called both at startup and in the event a thread dies.
        This function blocks at first startup until both threads are started.
        """
        req_targets = [self.thread_rabbit, self.thread_postgres]

        if self.shutting_down:
            return
        
        for target in req_targets:
            if target in self.threads and self.threads[target].is_alive():
                continue

            self.threads[target] = self.thread_spawn(target=target,
                    name=target.__name__)

        logger.info("Waiting for HTTPProxyClient thread startup.")
        while not self.rabbit_first_start or \
                not self.postgresql_first_start:
            time.sleep(0.1)

    def threads_shutdown(self) -> None:
        """
        This function attempts to safely shutdown all threads. It is called
        when the calling process is being shut down.
        """
        logger.info("Stopping consumption of queues.")
        if self.rabbit_connection is not None and self.channel is not None:
            self.rabbit_connection.add_callback_threadsafe(self.channel.stop_consuming)

        logger.info("Shutting down Postgres thread.")
        self.shutting_down = True

        logger.info("Exited.")

    def threads_alive(self) -> bool:
        """
        Checks that all threads are currently alive.

        Returns:
            bool: True if all threads are alive, False if at least one thread
                is currently dead.
        """
        
        if len(self.threads) == 0:
            return False

        for thread in self.threads.values():
            if not thread.is_alive():
                return False

        return True

    def thread_spawn(self, target:Callable, name:str) -> threading.Thread:
        """
        Spawns a thread that calls the callable.

        Args:
            @see https://docs.python.org/3/library/threading.html#threading.Thread

        Return: 
            thread: the newly started thread.
        """
        thread = threading.Thread(target=target, name=name)
        thread.start()

        return thread

    def thread_postgres_write(self, items_to_write:dict[str, list[RequestResponse]]) -> None:
        """
        Called when data is successfully read from the queue. Handles database
        writes.

        Args:
            items_to_write: a dictionary containing lists of RequestResponses
                grouped by target_guids.
        """
        for target_guid in items_to_write:
            try:
                with database_connect(target_guid, create=False) as conn:
                    logger.debug("Adding %s items for schema %s" % (len(items_to_write[target_guid]), target_guid))

                    for req_res in items_to_write[target_guid]:
                        normalised_pretty_url = EndpointMetadata.normalise_pretty_url(str(req_res.pretty_url))

                        stmt = select(EndpointMetadata).where(and_(EndpointMetadata.pretty_url == normalised_pretty_url, # type:ignore 
                            EndpointMetadata.method == req_res.method))

                        em = conn.execute(stmt).scalar()

                        if em is None:
                            em = EndpointMetadata(pretty_url=normalised_pretty_url, method=req_res.method)
                            conn.add(em)
                            conn.commit()
                        else:
                            # We don't want to fill the database with very
                            # noisy endpoints.
                            if len(em.request_responses) > self.MAX_REQ_RESPS:
                                logger.debug("Skip adding for %s because we exceeded MAX_REQ_RESPS")
                                continue

                        req_res.metadata_id = em.id
                        conn.add(req_res)

                    conn.commit()
            except InvalidSchemaException:
                logger.error("Invalid schema %s in header." % target_guid)
                continue

    def thread_postgres_read_queue(self) -> None:
        """
        This function gets called periodically by `self.thread_postgres`.
        Handles a single iteration of reading from the queue.
        """
        items_to_write : Dict[str, list[RequestResponse]] = {}
        items_read = 0
        try:
            while items_read < self.MAX_BULK_WRITE:
                dwi = self.db_write_queue.get_nowait()
                if dwi.target_guid not in items_to_write:
                    items_to_write[dwi.target_guid] = []

                items_to_write[dwi.target_guid].append(RequestResponse.createFromDWI(dwi))
                items_read += 1
        except queue.Empty:
            pass

        if items_read > 0:

            # Avoid polluting EndpointMetadata with fuzzer-generated
            # garbage. Requests can be created by fuzzer if an issue is
            # found.
            if self.is_fuzzer:
                return

            logger.debug("Writing %s requests to database." % items_read)

            try:
                self.thread_postgres_write(items_to_write)
            except exc.SQLAlchemyError:
                logger.exception("Unhandled SQL error while writing to DB:")

    def thread_postgres(self) -> None:
        """
        Main thread for connections to PostgreSQL and regular insertion of
        rows.

        A queue of request/responses pending writes, located at
        `self.db_write_queue`, is regularly popped in this function. It
        monitors `self.shutting_down`, if set to true dies.

        The general idea is that writes are handled outside of the mitmdump
        thread so that database writes do not influence the proxy's response
        speed times. One connection per database schema is maintained, for more
        information see `unicornbottle.database`.
        """
        logger.info("PostgreSQL thread starting")
        self.postgresql_first_start = True
        try:
            while True:
                if self.shutting_down:
                    break

                self.thread_postgres_read_queue()

                time.sleep(0.05)
        except:
            logger.exception("Exception in PostgreSQL thread")
            raise
        finally:
            logger.error("PostgreSQL thread is shutting down. See log for details.")

    def thread_rabbit(self) -> None:
        """
        Initializes the responses queue and handles consumption of responses.
        This is a blocking function and should be called in a new Thread.
        """
        try:
            self.rabbit_connection = rabbitmq_connect()
            self.channel = self.rabbit_connection.channel()

            # Create a queue for handling the responses.
            result = self.channel.queue_declare(queue='', exclusive=True)
            self.callback_queue = result.method.queue
            self.channel.basic_consume(
                queue=self.callback_queue,
                on_message_callback=self.on_response,
                auto_ack=True)

            self.rabbit_first_start = True
            logger.info("RabbitMQ thread ready to start consuming")
            self.channel.start_consuming() 
        except:
            logger.exception("Exception in RabbitMQ thread")
            raise
        finally:
            logger.error("RabbitMQ thread is shutting down. See log above for details.")
            if self.rabbit_connection:
                self.rabbit_connection.close()

            # Ensure variables are unset if threads die.
            self.rabbit_connection = None
            self.channel = None

    def on_response(self, ch : Any, method : Any, props : pika.spec.BasicProperties, body : bytes) -> None:
        """
        Gets called when a response is issued as per the RPC pattern.

        Args: 
            see https://pika.readthedocs.io/en/stable/modules/channel.html#pika.channel.Channel.basic_consume

        See:
            https://www.rabbitmq.com/tutorials/tutorial-six-python.html
        """
        with self.lock:
            if props.correlation_id is None:
                logger.error("Received message without correlation id?")
                return

            if props.correlation_id in self.corr_ids:
                self.responses[props.correlation_id] = body
                del self.corr_ids[props.correlation_id]
            else:
                logger.debug("Received message whose corr_id we're not currently tracking. corr_id: %s" % props.correlation_id)

    def target_guid_valid(self, val:str) -> bool:
        """
        Simple utility function to perform basic checks on the user-provided
        UUID.

        Args:
            val: the value to check.

        See:
            https://stackoverflow.com/a/54254115
        """
        try:
            uuid.UUID(str(val))
            return True
        except ValueError:
            return False

    def target_guid(self, request:mitmproxy.net.http.Request) -> str:
        """
        Obtain target guid from request.

        Args:
            request: the request to get the target_guid from.

        Returns:
            the target GUID or SKIP_DB_WRITE constant. If the return value of
            this function is SKIP_DB_WRITE, this request will not be written to
            the database write queue in `send_request`.
        """
        try:
            target_guid = request.headers[self.UB_GUID_HEADER]
            if not self.target_guid_valid(target_guid):
                target_guid = SKIP_DB_WRITE
        except KeyError:
            target_guid = SKIP_DB_WRITE

        return str(target_guid)

    def modify_headers(self, request: mitmproxy.net.http.Request) -> mitmproxy.net.http.Request:
        """
        Modify headers prior to sending. In particular, strip any X-UB headers
        and add X-Hackerone: benteveo header for traffic tagging.
        """
        request.headers['X-Hackerone'] = 'benteveo'

        # Brotli? encoding causes misterious issues.
        try:
            del request.headers['Accept-Encoding']
        except KeyError:
            pass

        return request

    def send_retry(self, request : mitmproxy.net.http.Request, corr_id:Optional[str]=None, attempts_left:int=3, timeout:Optional[float]=None) -> mitmproxy.net.http.Response:
        """
        Wrapper for send_request that retries.

        Args:
            See send_request.

            attempts_left: the number of attempts that are remaining for this
                request. We generally retry requests a couple of times.
        """
        
        if attempts_left == 0:
            raise UnableToProxyException("Could not send request")

        try:
            resp = self.send_request(request, corr_id, timeout=timeout)
            if resp.status_code == 502 or resp.status_code == 504: # proxy error codes we generate.
                raise UnableToProxyException("Could not proxy request. Response: %s" % resp.text)
            else:
                return resp
        except RetriableException:
            logger.debug("Going to retry, got exception when sending request.")
            return self.send_retry(request=request, corr_id=corr_id,
                    attempts_left=attempts_left-1, timeout=timeout)

    def log_publish_callback(self, corr_id:str, callback:Callable, *args:Any, **kwargs:Any) -> Any:
        """
        Simple wrapper for basic publish for the purpose of debug logging. It
        can be handy when debugging when the callback actually gets called. 
        """
        logger.debug("%s: Executing basic_pub." % (corr_id))
        return callback(*args, **kwargs)

    def send_request(self, request : mitmproxy.net.http.Request, corr_id:Optional[str]=None, timeout:Optional[float]=None) -> mitmproxy.net.http.Response:
        """
        Serialize and send the request to RabbitMQ, receive the response and
        unserialize.

        THIS FUNCTION IS CALLED BY MULTIPLE THREADS. Special care is needed in
        order to comply with pika's threading model. In short:

        - Calls to connection or channel objects need to be done using the
          add_callback_threadsafe function. 
        - More information here:
            https://github.com/pika/pika/blob/0.13.1/examples/basic_consumer_threaded.py
            https://stackoverflow.com/questions/55373867/how-to-add-multiprocessing-to-consumer-with-pika-rabbitmq-in-python
            https://stackoverflow.com/questions/65516220/what-is-the-use-of-add-callback-threadsafe-method-in-pika

        Handles writing to queue, polling until a response is received and timeouts.

        Args:
            request: A mitmproxy Request object.
            corr_id: the correlation id for this request, a uuid. If none is
                provided, one will be generated.
            timeout: the timeout for this request. If None,
                self.REQUEST_TIMEOUT will be used.

        Raises:
            TimeoutException: self.REQUEST_TIMEOUT/user-provided timeout exceeded, request timeout.
            NotConnectedException: We're currently not connected to AMQ. Will
                attempt to reconnect so that next `call` is successful.
            UnauthorizedException: Missing or malformed X-UB-GUID header. This
                serves as a form of precarious auth.
        """
        target_guid = self.target_guid(request)
        if not corr_id:
            corr_id = str(uuid.uuid4()) 

        request = self.modify_headers(request)

        try:
            if not self.threads_alive() or (self.rabbit_connection is None or self.channel is None):
                logger.error("One or more threads are dead. Attempting to restart and sending error to client.")
                self.threads_start()
                raise NotConnectedException("Not connected. Please retry in a jiffy.") # still raise. Clients must retry.

            logger.debug("%s:Created corr_id in dict" % (corr_id))
            self.corr_ids[corr_id] = True

            message_body = Request(request.get_state()).toJSON() # type:ignore
            timeout_millis = str(self.REQUEST_TIMEOUT * 1000) # Make use of TTL:
                # https://www.rabbitmq.com/ttl.html to prevent wasting time.

            basic_pub = partial(self.log_publish_callback, corr_id, self.channel.basic_publish, exchange='', routing_key='rpc_queue',
                properties=pika.BasicProperties(reply_to=self.callback_queue, correlation_id=corr_id, expiration=timeout_millis,),
                body=message_body)
            self.rabbit_connection.add_callback_threadsafe(basic_pub)

            logger.debug("%s:Sent to add_callback_threadsafe." % (corr_id))

            response = self.get_response(corr_id, request_timeout=timeout, pretty_url=request.pretty_url)
        except Exception as e:
            if target_guid != SKIP_DB_WRITE:
                # Couldn't successfully retrieve a response for this request. Still write to DB.
                exc_info = ExceptionSerializer(type(e).__name__, str(e), traceback.format_exc())
                dwr = DatabaseWriteItem(target_guid=target_guid, request=request,
                        response=None, exception=exc_info)

                self.db_write_queue.put(dwr)

            raise
        else:
            if target_guid != SKIP_DB_WRITE:
                dwr = DatabaseWriteItem(target_guid=target_guid, request=request,
                        response=response, exception=None)

                self.db_write_queue.put(dwr)

        return response

    def get_response(self, corr_id:str, request_timeout:Optional[float], pretty_url:Optional[str]=None) -> mitmproxy.net.http.Response:
        """
        This function reads from `self.responses[corr_id]` in a BLOCKING
        fashion until either a response is populated by the queue reader or
        `self.REQUEST_TIMEOUT` is exceeded.

        `self.responses` is populated by `self.on_response()`.

        Args:
            corr_id: The correlation ID for this request.
            request_timeout: how much to wait before raising TimeoutException. If None self.REQUEST_TIMEOUT is used.
            pretty_url: the pretty url for logging output only.
        """

        if not request_timeout:
            request_timeout = self.REQUEST_TIMEOUT

        start = time.time()
        try:
            while True:
                resp = None
                try:
                    resp = self.responses[corr_id]
                except KeyError:
                    pass

                timeout_exceeded = time.time() - start >= request_timeout

                if (not resp and timeout_exceeded) or self.shutting_down:
                    log_message = "%s: Timeout exceeded after %ss. Len responses: %s" % (corr_id, request_timeout, len(self.responses))
                    if pretty_url:
                        log_message += ". For url '%s'" % pretty_url

                    raise TimeoutException(log_message)
                elif resp:
                    return Response.fromJSON(self.responses[corr_id]).toMITM()

                time.sleep(0.05) 
        finally:
            with self.lock:
                try:
                    del self.corr_ids[corr_id]
                except KeyError:
                    pass

                try:
                    del self.responses[corr_id]
                except KeyError:
                    pass


