from enum import Enum
from typing import Dict, Optional, Any, Union, TypeVar, Type, List, Tuple
import base64
import json
import mitmproxy.net.http

MS = TypeVar('MS', bound='MessageSerializer')

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
    def fromJSON(cls : Type[MS], json_str : Union[bytes, str]) -> MS:
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
        Grabs data stored in the request state and converts it into a
        mitmproxy.http.Request object.
        """
        return mitmproxy.net.http.Request(**self.state)

class Response(MessageSerializer):
    def toMITM(self) -> mitmproxy.net.http.Response:
        """
        Grabs data stored in the request state and converts it into a
        mitmproxy.http.Response object.
        """
        return mitmproxy.net.http.Response(**self.state)

class ExceptionSerializer(MessageSerializer):
    """
    Stores information about an exception.
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

class InvalidFuzzLocation(Exception):
    pass

class FuzzParamType(Enum):
    PARAM_URL = 1
    PARAM_BODY = 2
    PARAM_MULTIPART = 3
    PARAM_JSON = 4
    HEADER = 5

class FuzzLocation():
    """
    This class represents a location within a HTTP Request where we will be
    inserting payloads. 
    
    It inherits from Request because the orignal request information is stored
    within it and is used for the generation of modified HTTP requests.
    """

    def __init__(self, state:dict, param_type:FuzzParamType, param_name:str):
        """
        Main constructor.

        Args:
            state: request state as exported by the
                mitmproxy.Request.get_state() method.
            param_type: fuzz parameter type. see `FuzzParamType`.
            param_name: parameter name.
        """
        self.base_request_state = state

        self.param_type = param_type
        self.param_name = param_name

    def fuzz(self, value:str) -> mitmproxy.net.http.Request:
        """
        Inserts the value at the insertion point.

        Args:
            value: the value to insert into the request.
        """
        request = mitmproxy.net.http.Request(**dict(self.base_request_state))

        if self.param_type == FuzzParamType.PARAM_URL:
            request.query[self.param_name] = value
        elif self.param_type == FuzzParamType.PARAM_BODY:
            if request.urlencoded_form:
                request.urlencoded_form[self.param_name] = value
            else:
                raise InvalidFuzzLocation("Can't insert into urlencoded form.")
        elif self.param_type == FuzzParamType.PARAM_MULTIPART:
            if request.multipart_form:
                request.multipart_form[self.param_name.encode('utf-8')] = value
            else:
                raise InvalidFuzzLocation("Can't insert into multipart form.")
        elif self.param_type == FuzzParamType.PARAM_JSON:
            body_json = json.loads(request.content)
            body_json[self.param_name] = value
            request.text = json.dumps(body_json)
        elif self.param_type == FuzzParamType.HEADER:
            request.headers[self.param_name] = value

        return request

    @staticmethod
    def generate(request:mitmproxy.net.http.Request) -> List:
        """
        Generates fuzz locations based on a request.

        Args:
            request: a mitm http request.

        Returns: 
            A list of fuzz locations.
        """

        return []
