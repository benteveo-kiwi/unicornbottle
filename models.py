from sqlalchemy import Column, Integer, String, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from typing import Dict, Optional, Any, Union, TypeVar, Type
import base64
import json
import mitmproxy.net.http

RR = TypeVar('RR', bound='RequestResponse')
MS = TypeVar('MS', bound='MessageSerializer')

Base : Any = declarative_base()
        
class RequestEncoder(json.JSONEncoder):
    """
    Performs encoding of byte arrays as base64. The rationale for doing this is
    to prevent having to deal with every known encoding known in the universe
    and instead transmit bytes as they are.

    Byte arrays that are encoded are prefixed by "application/base64:" in order
    to facilitate detection of base64 by the decoder.
    """
    def default(self, obj : Any) -> Any:
        if isinstance(obj, (bytes, bytearray)):
            encoded = base64.b64encode(obj).decode("ascii")
            return "application/base64:" + encoded

        return json.JSONEncoder.default(self, obj)

class RequestDecoder(json.JSONDecoder):
    """
    Decodes requests encoded by RequestEncoder.

    Recursively iterates through all objects and decodes strings if they match
    the required prefix.
    """
    def __init__(self, *args, **kwargs) -> None: #type:ignore
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def decode_base64(self, string : str) -> Union[str, bytes]:
        """
        Decodes strings and returns the corresponding bytes if they are base64
        
        Args:
            string: the input string decode or leave as is.
        """
        if string.startswith("application/base64:"):
            splat = string.split(":")
            return base64.b64decode(splat[1])
        else:
            return string

    def object_hook(self, data : Any) -> Any:
        if isinstance(data, (dict, list)):
            for k, v in (data.items() if isinstance(data, dict) else enumerate(data)):
                if isinstance(v, str):
                    data[k] = self.decode_base64(v)

                self.object_hook(v)

        return data

class MessageSerializer():
    def __init__(self, state : dict) -> None:
        """
        Internal representation of request/response objects for the proxy and
        server instances. Can be used to transmit mitmproxy's internal
        representations.

        Args:
            state: request state as exported by the
                mitmproxy.Request.get_state() method.
        """

        self.state = state

    def toJSON(self) -> str:
        """
        Converts the object into a JSON string. Byte arrays are encoded into
        base64.
        """

        data = self.state
        return json.dumps(data, cls=RequestEncoder)

    @classmethod
    def fromJSON(cls : Type[MS], json_str : bytes) -> MS:
        """
        Creates a Request object from a JSON string.

        Raises:
            json.decoder.JSONDecodeError: if you give it bad JSON.
        """
        j = json.loads(json_str)
        state = json.loads(json_str, cls=RequestDecoder)
        return cls(state)

class Request(MessageSerializer):
    def toMITM(self) -> mitmproxy.net.http.Request:
        """
        Grabs data stored in the request state and converts it into a mitmproxy.http.Request object.
        """
        return mitmproxy.net.http.Request(**self.state)

class Response(MessageSerializer):
    def toMITM(self) -> mitmproxy.net.http.Response:
        """
        Grabs data stored in the request state and converts it into a mitmproxy.http.Response object.
        """
        return mitmproxy.net.http.Response(**self.state)

class ExceptionSerializer(MessageSerializer):
    """
    Grabs information about an exception.
    """

    def __init__(self, type:str, value:str, tb:str):
        self.state : Dict[str, str] = {}

        self.state["type"] = type
        self.state["value"] = value
        self.state["tb"] = tb

class DatabaseWriteItem():
    """
    Simple data structure for communication between the `send_request` thread
    and the `thread_postgres` thread.
    """
    def __init__(self, target_guid:str, request:mitmproxy.net.http.Request,
            response:Optional[mitmproxy.net.http.Response], exception:Optional[ExceptionSerializer]) -> None:
        """
        Default constructor.

        Args:
            target_guid: the guid sent in the X-UB-GUID header.
            request: the `Request` associated with this entry.
            response: the response. May be null if an error occurred that
                prevented the retrieval of the response, such as a timeout.
            exception: the exception associated with this failure. May be None if
                there were no errors.
        """
        self.target_guid = target_guid
        self.request = request
        self.response = response
        self.exception = exception

class EndpointMetadata(Base):
    """
    This table contains metadata related to particular endpoints. Endpoints are
    defined as (`pretty_url`,`method`) pairs. This may encompass several
    `RequestResponses` if more than one request has ever been recorded for an
    endpoint.
    """
    __tablename__ = "endpoint_metadata"
    __table_args__ = (UniqueConstraint('pretty_url', 'method', name='_url_method_uc'),)

    id = Column(Integer, primary_key=True)
    pretty_url = Column(String, index=True)
    method = Column(String, index=True)

    fuzz_count = Column(Integer, default=0)
    crawl_count = Column(Integer, default=0)

    request_responses = relationship("RequestResponse")

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
    metadata_id = Column(Integer, ForeignKey('endpoint_metadata.id'), nullable=False)
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

    @classmethod
    def createFromDWI(cls, dwi:DatabaseWriteItem) -> RR:
        """
        Helper method for creating a `RequestResponse` object from a `models.DatabaseWriteItem`

        Args:
            dwi: Input `DatabaseWriteItem`.
        """
        exc = None
        if dwi.exception is not None:
            exc = dwi.exception.toJSON()

        resp = None
        resp_status_code=None
        if dwi.response is not None:
            resp = Response(dwi.response.get_state()).toJSON() #type: ignore
            resp_status_code=dwi.response.status_code

        req = Request(dwi.request.get_state()).toJSON() #type: ignore
            
        return cls(pretty_url=dwi.request.pretty_url,
                pretty_host=dwi.request.pretty_host, path=dwi.request.path,
                scheme=dwi.request.scheme, port=dwi.request.port,
                method=dwi.request.method,
                response_status_code=resp_status_code,
                exception=exc,
                request=req,
                response=resp)
