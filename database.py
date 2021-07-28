from sqlalchemy import Column, Integer, String, JSON
from sqlalchemy import create_engine, engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from typing import Any, Optional, TypeVar
from unicornbottle.environment import read_configuration_file
from urllib.parse import quote  
import configparser
import mitmproxy.net.http
import sqlalchemy

RR = TypeVar('RR', bound='RequestResponse')
Base : Any = declarative_base()

CONFIG_FILE = '/home/cli/.cli.conf'

class InvalidSchemaException(Exception):
    pass

class DatabaseWriteItem():
    """
    Simple data structure for communication between the `send_request` thread
    and the `thread_postgres` thread.
    """
    def __init__(self, target_guid:str, request:mitmproxy.net.http.Request,
            response:Optional[mitmproxy.net.http.Response], exception:Optional[Exception]) -> None:
        """
        Default constructor.

        Args:
            target_guid: the guid sent in the X-UB-GUID header.
            request: the `Request` associated with this entry.
            response: the response. May be null if an error occurred that
                prevented the retrieval of the response, such as a timeout.
            exception: the exception associated with this failure. May be None if
                there were no errors
        """
        self.target_guid = target_guid
        self.request = request
        self.response = response
        self.exception = exception

class RequestResponse(Base):
    """
    This table contains the requests sent through the proxy and, if there are
    any, also information regarding either the response or the error. These map
    almost 1:1 to attributes that are present in the `mitmproxy` API
    documentation, so if you need more information regarding any of the fields
    you can also find information there.

    The following columns are not part of that API:

    - fuzz_count: number of times we have fuzzed this endpoint.
    - crawl_count: the number of times we have initiated a crawl from this URL.
      Our crawling strategy is recursive and time-bound so we prioritize
      starting from endpoints we have not yet scanned from where we can.

    Please note that a different schema is used for each "target", in order to
    avoid all requests ever sent through the proxy from being stored in a
    single database table and make performance tuning a little simpler.

    @see https://docs.mitmproxy.org/dev/api/mitmproxy/http.html#Request
    @see https://docs.mitmproxy.org/dev/api/mitmproxy/http.html#Response
    """
    __tablename__ = "request_response"

    id = Column(Integer, primary_key=True)
    pretty_url = Column(String, index=True)
    pretty_host = Column(String, index=True)
    path = Column(String, index=True)
    scheme = Column(String)
    port = Column(Integer)
    method = Column(String)
    response_status_code = Column(Integer)
    exception = Column(JSON)
    request = Column(JSON)
    response = Column(JSON)
    fuzz_count = Column(Integer)
    crawl_count = Column(Integer)

    @classmethod
    def createFromDWI(cls, dwi:DatabaseWriteItem) -> RR:
        """
        Helper method for creating a `RequestResponse` object from a `models.DatabaseWriteItem`

        Args:
            dwi: Input `DatabaseWriteItem`.
        """

        exc = None # https://stackoverflow.com/questions/8238360/how-to-save-traceback-sys-exc-info-values-in-a-variable
        if dwi.exception is not None:
            pass

        resp = None
        resp_status_code=None
        if dwi.response is not None:
            resp = dwi.response.get_state() #type: ignore
            resp_status_code=dwi.response.status_code

        req = dwi.request.get_state() #type: ignore
            
        return cls(pretty_url=dwi.request.pretty_url,
                pretty_host=dwi.request.pretty_host, path=dwi.request.path,
                scheme=dwi.request.scheme, port=dwi.request.port,
                method=dwi.request.method,
                response_status_code=resp_status_code,
                exception=exc,
                request=req,
                response=resp,
                fuzz_count=0,
                crawl_count=0)

def get_url() -> str:
    """
    Get the configuration file and create a properly escaped connection string.
    """
    config = read_configuration_file() 
    
    db = config['database']

    return "postgresql://%s:%s@%s/%s" % (quote(db['username']),
            quote(db['password']), quote(db['hostname']),
            quote(db['database']))

def database_connect(schema : str, create:bool) -> Session:
    """
    Use SQLAlchemy to connect to the database. If the tables or schemas do not
    exist then they will be created.

    Args:
        schema: PostgreSQL schema name to use for all queries.
        create: Create tables in this schema if they do not exist. Note that if
            the schema already exists, no creation will occur.

    Raises:
        InvalidSchemaException: if a non-existent schema is provided and the
            create parameter is false. 

    Returns:
        session: the SQL alchemy session.
    """

    # Instruct the engine to use the schema for all queries.
    url = get_url()
    engine = create_engine(url).execution_options(
            schema_translate_map={None: schema}) # type:ignore

    # Create schemas and tables
    if not engine.dialect.has_schema(engine, schema):
        if create:
            engine.execute(sqlalchemy.schema.CreateSchema(schema))
            Base.metadata.create_all(bind=engine)
        else:
            raise InvalidSchemaException("Target %s does not exist" % schema)

    # Arcane incantations to satistfy Mypy.
    Sess = sessionmaker(bind=engine)
    session : Session = Sess()

    return session
