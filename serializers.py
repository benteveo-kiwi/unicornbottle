from enum import IntEnum
from mitmproxy.net.http.http1 import assemble
from typing import Dict, Optional, Any, Union, TypeVar, Type, List, Tuple
import base64
import json
import mitmproxy.net.http
import os
import subprocess
import tempfile
import uuid

MS = TypeVar('MS', bound='MessageSerializer')
FL = TypeVar('FL', bound='FuzzLocation')
PB = TypeVar('PB', bound='Pingback')

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

    def toPlain(self) -> str:
        """
        Returns the raw data as hopefully would be sent in the wire.
        """
        request = self.toMITM()

        request.decode(strict=False)
        raw_request:bytes = assemble.assemble_request(request) # type: ignore

        return raw_request.decode('utf-8')

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
    def __init__(self, request:mitmproxy.net.http.Request, response:Optional[mitmproxy.net.http.Response], 
            exception:Optional[ExceptionSerializer]=None, target_guid:Optional[str]=None) -> None:
        """
        Default constructor.

        Args:
            request: the `Request` associated with this entry.
            response: the response. May be null if an error occurred that
                prevented the retrieval of the response, such as a timeout.
            exception: the exception associated with this failure. May be None if
                there were no errors.
            target_guid: the guid sent in the X-UB-GUID header. If None it will
                be retrieved from the request headers.
        """
        self.request = request
        self.response = response
        self.exception = exception

        if target_guid:
            self.target_guid = target_guid
        else:
            self.target_guid = self.request.headers['X-UB-GUID']

class InvalidFuzzLocation(Exception):
    pass

class FuzzParamType(IntEnum):
    PARAM_URL = 1
    PARAM_BODY = 2
    PARAM_MULTIPART = 3
    PARAM_JSON = 4
    HEADER = 5

class InvalidLoginScript(Exception):
    pass

class FuzzLocation():
    """
    This class represents a location within a HTTP Request where we will be
    inserting payloads. 
    
    It inherits from Request because the orignal request information is stored
    within it and is used for the generation of modified HTTP requests.
    """

    def __init__(self, target_guid:str, target_id:int, req_resp_id:int,
            em_id:int, state:dict, param_type:FuzzParamType, param_name:str,
            login_script:Optional[str]=None):
        """
        Main constructor.

        Args:
            target_guid: the guid sent in the X-UB-GUID header.
            target_id: the numeric target ID for this target. The reason this
                is required is the fuzzer needs it for pingback payload generation.
            req_resp_id: the unique id for this request_response object as
                stored in the database.
            em_id: endpoint metadata id as associated with this req_resp.
                Required to prevent unnecessary DB calls in fuzzer and keep
                that component simple and self-contained.
            state: request state as exported by the
                mitmproxy.Request.get_state() method.
            param_type: fuzz parameter type. see `FuzzParamType`.
            param_name: parameter name.
            login_script: login script if required to fuzz this endpoint. The
                login script is called only once per FuzzLocation.
        """
        self.target_guid = target_guid
        self.target_id = target_id
        self.req_resp_id = req_resp_id
        self.em_id = em_id
        self.base_request_state = state

        self.param_type = param_type
        self.param_name = param_name
        self.login_script = login_script

        self.login_data:Optional[dict] = None
        self.tmp_filename = "/tmp/%s.temp" % uuid.uuid4()

    def __repr__(self) -> str:
        return "<FuzzLocation %s (%s)>" % (self.param_name, self.param_type)

    def get_login_data(self) -> dict:
        """
        On the first run, we execute login_script and obtain the data.
        Subsequent runs return cached data.
        """
        
        if self.login_script is None:
            raise InvalidLoginScript("Called without a login_script.")

        if self.login_data is None:
            try:
                if not all(c.isdigit() or c.islower() or c == "_" for c in self.login_script):
                    raise InvalidLoginScript("Invalid login_script %s" % self.login_script)

                # We can call passwordless sudo here because of an entry in /etc/sudoers created by SaltStack.
                subprocess.call(["sudo", "-u", "crawler", "node", "/home/crawler/ub-crawler/src/login/"+self.login_script+".js", self.tmp_filename])


                self.login_data = json.loads(open(self.tmp_filename, 'r').read())

                if self.login_data is None:
                    raise InvalidLoginScript()

                return self.login_data
            finally:
                # Can't call unlink because file is owned by crawler.
                subprocess.call(["sudo", "-u", "crawler", "rm", self.tmp_filename])
            
        else:
            return self.login_data
    
    def authenticate_request(self, req:mitmproxy.net.http.Request) -> mitmproxy.net.http.Request:
        """
        Authenticates a request. This is done by calling the login script and
        parsing the output file. 
        """
        login_data = self.get_login_data()
        for cookie in login_data['cookies']:

            req.cookies[cookie['name']] = cookie['value']

        return req

    def get_baseline(self) -> mitmproxy.net.http.Request:
        """
        Gets the request to fuzz without any modifications except for
        authentication. If authentication is required for this fuzz location,
        it authenticates the request prior to returning it.
        """
        request = mitmproxy.net.http.Request(**dict(self.base_request_state))
        if self.login_script:
            request = self.authenticate_request(request)

        return request

    def get_base_value(self) -> Any:
        """
        Returns the value that is present in the parameter being fuzzed.
        """
        request = self.get_baseline()
        if self.param_type == FuzzParamType.PARAM_URL:
            return request.query[self.param_name]
        elif self.param_type == FuzzParamType.PARAM_BODY:
            return request.urlencoded_form[self.param_name]
        elif self.param_type == FuzzParamType.PARAM_MULTIPART:
            return request.multipart_form[self.param_name.encode('utf-8')]
        elif self.param_type == FuzzParamType.PARAM_JSON:
            body_json = json.loads(request.content)
            return body_json[self.param_name]
        elif self.param_type == FuzzParamType.HEADER:
            return request.headers[self.param_name]
        else:
            raise Exception("Unhandled FuzzParamType")

    def fuzz(self, value:str) -> mitmproxy.net.http.Request:
        """
        Inserts the value at the insertion point. If a login script has been
        set on the constructor then we are going to attempt to authenticate

        Args:
            value: the value to insert into the request.
        """
        request = self.get_baseline()

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
        else:
            raise Exception("Unhandled FuzzParamType")

        return request

    @staticmethod
    def generate(target_guid:str, target_id:int, req_resp_id:int, em_id:int,
            request:mitmproxy.net.http.Request,
            login_script:Optional[str]=None) -> List:
        """
        Generates fuzz locations based on a request.

        Args:
            target_guid: the guid sent in the X-UB-GUID header.
            target_id: the numeric target ID for this target.
            req_resp_id: the unique id for this request_response object as
                stored in the database.
            em_id: endpoint metadata id as associated with this req_resp.
                Required to prevent unnecessary DB calls in fuzzer and keep
                that component simple and self-contained.
            request: a mitm http request.
            login_script: the login_scripts for these fl.

        Returns: 
            A list of FuzzLocation.
        """

        base_kwargs = {
            "target_guid": target_guid,
            "target_id": target_id,
            "req_resp_id": req_resp_id,
            "em_id": em_id,
            "state": request.get_state(),
            "login_script": login_script,
        }

        fuzz_locations = []
        for param_type in FuzzParamType:

            if param_type == FuzzParamType.PARAM_URL:
                for param in request.query:
                    fuzz_locations.append(FuzzLocation(param_type=FuzzParamType.PARAM_URL, param_name=param, **base_kwargs))

            elif param_type == FuzzParamType.PARAM_BODY:
                for param in request.urlencoded_form:
                    fuzz_locations.append(FuzzLocation(param_type=FuzzParamType.PARAM_BODY, param_name=param, **base_kwargs))

            elif param_type == FuzzParamType.PARAM_MULTIPART:
                for param in request.multipart_form:
                    fuzz_locations.append(FuzzLocation(param_type=FuzzParamType.PARAM_MULTIPART, param_name=param, **base_kwargs))

            elif param_type == FuzzParamType.PARAM_JSON:
                try:
                    body_json = json.loads(request.content)
                except json.JSONDecodeError:
                    continue

                for param in body_json:
                    fuzz_locations.append(FuzzLocation(param_type=FuzzParamType.PARAM_JSON, param_name=param, **base_kwargs))

            elif param_type == FuzzParamType.HEADER:
                for param in request.headers:
                    fuzz_locations.append(FuzzLocation(param_type=FuzzParamType.HEADER, param_name=param, **base_kwargs))

            else:
                raise Exception("Unhandled FuzzParamType.")

        return fuzz_locations

    def toJSON(self) -> str:
        """
        Converts the object into a JSON string. Byte arrays are encoded into
        base64.
        """
        
        data = {
            "target_guid": self.target_guid,
            "target_id": self.target_id,
            "req_resp_id": self.req_resp_id,
            "em_id": self.em_id,
            "state": self.base_request_state,
            "param_type": self.param_type,
            "param_name": self.param_name,
            "login_script": self.login_script
        }
        return json.dumps(data, cls=RequestEncoder)

    @classmethod
    def fromJSON(cls : Type[FL], json_str : Union[bytes, str]) -> FL:
        """
        Creates a Request object from a JSON string.

        Raises:
            json.decoder.JSONDecodeError: if you give it bad JSON, which would
                be _rude_.
        """
        j = json.loads(json_str, cls=RequestDecoder)
        
        try: 
            login_script = j['login_script']
        except KeyError:
            login_script = None

        return cls(j['target_guid'], j['target_id'], j['req_resp_id'],
                j['em_id'], j['state'], FuzzParamType(j['param_type']),
                j['param_name'], login_script)


class Pingback():
    """
    This class serves as a representation of a DNS pingback.
    """

    def __init__(self, domain:str, ip:str):
        """
        Main constructor.

        Args:
            domain: the full domain name. May contain a trailing dot: "google.com."
            ip: the IP which trigger this DNS request. Frequently this is the
                IP of the DNS resolver used by the target or similar.
        """
        self.domain = domain
        self.ip = ip

    def toJSON(self) -> str:
        return json.dumps(self.__dict__)

    @classmethod
    def fromJSON(cls : Type[PB], json_str : Union[bytes, str]) -> PB:
        """
        Creates a Pingback object from a JSON string.

        Raises:
            json.decoder.JSONDecodeError: if you very rudely give it bad JSON.
        """
        j = json.loads(json_str)
        state = json.loads(json_str, cls=RequestDecoder)

        return cls(state['domain'], state['ip'])
