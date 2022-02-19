from functools import total_ordering
from mitmproxy.net.http.http1 import assemble
from random import randint
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, JSON, ForeignKey, Boolean, Enum
from sqlalchemy import func
from sqlalchemy import or_, not_, and_, any_, all_
from sqlalchemy import UniqueConstraint, CheckConstraint
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import aliased
from sqlalchemy.orm import relationship, RelationshipProperty, Query
from sqlalchemy.orm.session import Session
from typing import Dict, Optional, Any, Union, TypeVar, Type, List, Tuple
from unicornbottle.serializers import Request, Response, ExceptionSerializer, DatabaseWriteItem
import enum
import json
import mitmproxy
import re

EM = TypeVar('EM', bound='EndpointMetadata')
RR = TypeVar('RR', bound='RequestResponse')
SE = TypeVar('SE', bound='Severity')
Base : Any = declarative_base()

STATIC_FILES = [
    '%.png', '%.gif', '%.jpg', '%.jpeg', '%.svg', '%.webp', '%.tif', '%.tiff', '%.css', '%.js', '%.mp4', '%.woff', '%.woff2', '%.json', '%.ico', '%.ttf', '%.pdf', '%.otf', '%.webm', '%.iso', '%.tar.gz', '%.mp3', '%.tar'
]

class InvalidScopeName(Exception):
    pass

class Platform(enum.Enum):
    H1 = "H1"

class Target(Base):
    """
    This table contains metadata regarding targets.
    """
    __tablename__ = "target"
    # See: https://docs.sqlalchemy.org/en/13/orm/extensions/declarative/table_config.html#table-configuration
    __table_args__ = (
        UniqueConstraint('name', 'platform'),
        {'schema': 'public'}
    )

    id = Column(Integer, primary_key=True)

    name = Column(String, nullable=False, index=True)
    platform = Column(Enum(Platform), nullable=True, index=True)
    guid = Column(UUID(), nullable=False, index=True, unique=True)
    active = Column(Boolean, default=False, index=True)

    assets : RelationshipProperty = relationship("Asset") 

    @staticmethod 
    def get_active_targets(db:Session) -> List[Tuple[str, str]]:
        """
        Retrieves a list of active bug bounties from the DB.
        """
        active_targets_tuple = db.query(Target).filter(Target.active == True).all()
        if len(active_targets_tuple) == 0:
            raise Exception("No active targets.")
        else:
            active_targets = []
            for at in active_targets_tuple:
                active_targets.append((at.guid, at.name))

        return active_targets
    @staticmethod
    def get_id_by_guid(db:Session, target_guid:str) -> int:
        """
        Gets a target ID given a target GUID.

        Args:
            target_guid: the guid to perform the search for. It will fail if the query fails to return exactly one row.
        """
        return int(db.query(Target.id).filter(Target.guid == target_guid).scalar())

class Asset(Base):
    """
    This table contains a representation of "assets" within the target BB.
    """
    __tablename__ = "asset"
    __table_args__ = {'schema': 'public'}

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('public.target.id'), nullable=False, index=True)

    type = Column(String, nullable=False, index=True)
    identifier = Column(String, nullable=True, index=True)
    description_str = Column(String, nullable=True)

class Scope(Base):
    """
    This table contains basic metadata regarding scope.
    """
    __tablename__ = "scope"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, index=True)

    urls : RelationshipProperty = relationship("ScopeURL") 

class ScopeURL(Base):
    """
    This table stores scope information for specific URLs. Only URLs explicitly
    included are crawled, and a login_script can optionally be used for each URL.

    PostgreSQL wildcards, like the ones used by the LIKE statement, are allowed
    on the pretty_url_like column. The "login_script" column refers to login
    scripts as used and defined by the crawler.

    The negative column determines whether this scope url is meant to be
    exclusionary, i.e. whether we should exclude URLs that match the
    pretty_url_like.
    """
    __tablename__ = "scope_url"
    __table_args__ = (UniqueConstraint('scope_id', 'pretty_url_like', name='_scope_purl_uc'),)

    id = Column(Integer, primary_key=True)
    scope_id = Column(Integer, ForeignKey('scope.id'), nullable=False, index=True)
    pretty_url_like = Column(String, nullable=False, index=True)
    login_script = Column(String)
    negative = Column(Boolean, default=False)

    @staticmethod
    def get_uncrawled(db:Session, scope_name:str) -> Query:
        """
        Gets a list of ScopeURLs that would return no matches from the
        EndpointMetadata table because they have never been crawled. This
        serves to populate the EndpointMetadata table on first runs.

        Args:
            db: the db as returned by `unicornbottle.database.database_connect`
            scope_name: the scope as stored in the `Scope.name` model.
        """
        try:
            scope = db.query(Scope).filter(Scope.name == scope_name).one()
        except NoResultFound:
            raise InvalidScopeName("A scope named %s does not exist in the schema" % scope_name)

        # Join.
        join_filter = (EndpointMetadata.pretty_url == func.replace(ScopeURL.pretty_url_like, '%', ''))
        rows:Query = db.query(ScopeURL, EndpointMetadata).join(EndpointMetadata, join_filter,
                        isouter=True).filter(ScopeURL.scope_id == scope.id, EndpointMetadata.id == None)

        rows = rows.filter(ScopeURL.negative == False)

        return rows

class EndpointMetadata(Base):
    """
    This table contains metadata related to particular endpoints. Endpoints are
    defined as (`pretty_url`,`method`) pairs. This may encompass several
    `RequestResponses` if more than one request has ever been recorded for an
    endpoint.
    """
    __tablename__ = "endpoint_metadata"
    __table_args__ = (
        UniqueConstraint('pretty_url', 'method', name='_url_method_uc'),
        CheckConstraint("(POSITION('?' in pretty_url) = 0 AND POSITION(';' in pretty_url) = 0)", name='normalised_pretty_url'),
    )

    id = Column(Integer, primary_key=True)
    pretty_url = Column(String, index=True)
    method = Column(String, index=True)

    crawl_count = Column(Integer, default=0, nullable=False) # Successful OR failed crawl count.

    # Crawl failed due to bad HTTP status code or bad URL in general.  The idea
    # is that these kinds of failures may occur even if there are no bugs in
    # our code. E.g. a broken link may trigger this error.
    crawl_fail_count = Column(Integer, default=0, nullable=False) 

    # Crawl failed due to unhandled exception.  These generally should be
    # indicative of a failure on our end to either handle a specific scenario,
    # and should not occur in normal operations. E.g. An error with the
    # login_script may trigger this flag.
    crawl_exception_count = Column(Integer, default=0, nullable=False) 

    fuzz_count = Column(Integer, default=0, nullable=False)
    fuzz_fail_count = Column(Integer, default=0, nullable=False) 
    fuzz_exception_count = Column(Integer, default=0, nullable=False) 

    request_responses : RelationshipProperty = relationship("RequestResponse") 

    def __repr__(self) -> str:
        return "<EndpointMetadata %s (%s) fuzz_count:%s crawl_count:%s crawl_fail_count:%s crawl_exception_count:%s>" % (self.pretty_url,
                self.method, self.fuzz_count, self.crawl_count, self.crawl_fail_count, self.crawl_exception_count)

    @staticmethod
    def get_endpoints_by_scope(db:Session, scope_name:str, limit:int,
            max_crawl_count:int=-1, method:Optional[str]=None,
            order_by:Union[List,Optional[Column]]=None,
            exclude_static:bool=True, max_fuzz_count:int=-1) -> Query:
        """
        Returns the query object required in order to get all endpoints filtered by scope.

        Args:
            db: the db as returned by `unicornbottle.database.database_connect`
            scope_name: the scope as stored in the `Scope.name` model.
            limit: Absolute maximum number of results to return.
            max_crawl_count: exclude rows with a `crawl_count` higher than this value.
            method: filter by method if present.
            order_by: order by. If not present, will sort by crawl_count asc.
            exclude_static: whether to exclude static looking urls, using a
                LIKE that matches urls that blatantly very much look like JS, SVG
                etc.
            max_crawl_count: exclude rows with a `fuzz_count` higher than this value.
        """
        try:
            scope = db.query(Scope).filter(Scope.name == scope_name).one()
        except NoResultFound:
            raise InvalidScopeName("A scope named %s does not exist in the schema" % scope_name)

        positive_scope = aliased(ScopeURL)
        positive_filter = (EndpointMetadata.pretty_url.like(positive_scope.pretty_url_like) & # type: ignore
                (positive_scope.scope_id == scope.id) & (positive_scope.negative == False)) 
        negative_scope = aliased(ScopeURL)
        negative_filter = (EndpointMetadata.pretty_url.like(negative_scope.pretty_url_like) & # type: ignore
                (negative_scope.scope_id == scope.id) & (negative_scope.negative == True))

        rows:Query = db.query(EndpointMetadata, positive_scope)\
                .join(positive_scope, positive_filter)\
                .join(negative_scope, negative_filter, isouter=True)\
                    .filter(negative_scope.id == None)

        # Filter.
        if exclude_static:
            rows = rows.filter(not_(EndpointMetadata.pretty_url.ilike(all_(STATIC_FILES))))
        if max_crawl_count != -1:
            rows = rows.filter(EndpointMetadata.crawl_count <= max_crawl_count)
        if max_fuzz_count != -1:
            rows = rows.filter(EndpointMetadata.fuzz_count <= max_fuzz_count)
        if method:
            rows = rows.filter(EndpointMetadata.method == method)

        # Order and Limit.
        if order_by:
            if isinstance(order_by, list):
                for clause in order_by:
                    rows = rows.order_by(clause)
            else:
                rows = rows.order_by(order_by)
        else:
            rows = rows.order_by(EndpointMetadata.crawl_count.asc(), func.random())

        if limit != -1:
            rows = rows.limit(limit)

        return rows

    @staticmethod
    def get_fuzz_endpoints(db:Session, scope_name:str, limit:int, max_fuzz_count:int) -> List[Tuple[EM, Optional[str]]]:
        """
        Gets endpoints that will be sent to the RabbitMQ queue as fuzz tasks.
        It gets these based on URLs already existing in EndpointMetadata.

        Args:
            db: the db as returned by `unicornbottle.database.database_connect`
            scope_name: the scope as stored in the `Scope.name` model.
            limit: maximum number of results to return from endpoint_metadata.
                Note that if less than those results are retrievable, we may return
                more data from any uncrawled_scopes.
            max_fuzz_count: exclude rows with a `crawl_count` higher than this value.
        """
        rows = EndpointMetadata.get_endpoints_by_scope(db, scope_name, limit,
                max_fuzz_count=max_fuzz_count, order_by=[EndpointMetadata.fuzz_count.asc(), func.random()])

        ret = []
        for result in rows.all():
            em, su = result
            ret.append((em, su.login_script))

        return ret

    @staticmethod
    def get_crawl_endpoints(db:Session, scope_name:str, limit:int, max_crawl_count:int) -> List[Tuple[str, Optional[str]]]:
        """
        Gets endpoints that will be sent to the RabbitMQ queue as crawl tasks.
        It gets these based on URLs already existing in EndpointMetadata, as
        well as on URLs present in the `scope_urls` table.

        Args:
            db: the db as returned by `unicornbottle.database.database_connect`
            scope_name: the scope as stored in the `Scope.name` model.
            limit: maximum number of results to return from endpoint_metadata.
                Note that if less than those results are retrievable, we may return
                more data from any uncrawled_scopes.
            max_crawl_count: exclude rows with a `crawl_count` higher than this value.
        """
        rows = EndpointMetadata.get_endpoints_by_scope(db, scope_name, limit, max_crawl_count)

        # Transform data to make it consumable by the RabbitMQ producer.
        urls = []
        for row in rows.all():
            endpoint_metadata = row[0]
            scope_url = row[1]

            login_script = None if scope_url is None else scope_url.login_script # scope_url is none 
                # when we login_script is none due to the query logic.

            # Because we normalise the URLs in EndpointMetadata to not have a query string,
            # therefore we need to get the querystring from there yonder,
            # within RequestResponse.
            nb_req_resp = len(endpoint_metadata.request_responses)
            if nb_req_resp > 0:
                crawl_url = endpoint_metadata.request_responses[randint(0, nb_req_resp - 1)].pretty_url # randomness makes everything better.
            else:
                crawl_url = endpoint_metadata.pretty_url

            crawl_tuple = (crawl_url, login_script)
            if crawl_tuple not in urls:
                urls.append(crawl_tuple)

        # Get URLs that have been added as a scope but never received an
        # initial scan.
        if len(urls) < limit:
            uncrawled_scope_urls = ScopeURL.get_uncrawled(db, scope_name)
            for row in uncrawled_scope_urls.all():
                scope_url, _ = row
                crawl_tuple = (scope_url.pretty_url_like.replace('%', ''), scope_url.login_script)
                if crawl_tuple not in urls:
                    urls.append(crawl_tuple)

        return urls

    @staticmethod
    def discovered_endpoints(db:Session, scope_name:str) -> List:
        """
        Obtains endpoints discovered.

        Args:
            db: the db as returned by `unicornbottle.database.database_connect`
            scope_name: the scope as stored in the `Scope.name` model.
        """
        rows = EndpointMetadata.get_endpoints_by_scope(db, scope_name,
                limit=-1, max_crawl_count=-1, method=None,
                order_by=EndpointMetadata.pretty_url)

        endpoints = []
        for row in rows.all():
            endpoint_metadata = row[0]
            endpoints.append(endpoint_metadata)

        return endpoints

    @staticmethod
    def normalise_pretty_url(pretty_url:str) -> str:
        """
        Perform normalisation computations on the input pretty_url as received
        from mitmproxy.
        
        The general idea behind this function is to aggregate similar URLs such as:

        http://www.example.com/test/?id=1
        http://www.example.com/test/?id=2

        This is currently achieved by splitting the string on "?" and ";" and
        returning element number 0. 
        """
        return str(re.split("\\?|;", pretty_url)[0])

    @staticmethod
    def crawl_finished(db:Session, pretty_url:str, update_crawl_count:bool, fail:bool, exception:bool) -> None:
        """
        Update or create an EndpointMetadata and set the right column values
        corresponding to a successful or failed crawl attempt.

        Please note that for historic reasons this method is called "finished"
        but is also called when the request is sent to the queue, i.e. when the
        crawl is started.

        Args:
            db: the db as returned by `unicornbottle.database.database_connect`
            pretty_url: as stored in the model.
            update_crawl_count: whether to update crawl count. This is updated
                when a crawl task is created, but not when a failure or
                exception is reported by a crawler.
            fail: whether the crawl failed.
            exception: whether the crawl exceptioned.
        """
        # If an endpoint for this URL doesn't exist, create it.
        normalised_pretty_url = EndpointMetadata.normalise_pretty_url(str(pretty_url))
        try:
            filter = (EndpointMetadata.pretty_url == normalised_pretty_url) & (EndpointMetadata.method == "GET")
            endpoint_metadata = db.query(EndpointMetadata).filter(filter).one()
        except NoResultFound:
            endpoint_metadata = EndpointMetadata(pretty_url=normalised_pretty_url, method="GET")
            db.add(endpoint_metadata)
            db.commit()

        if update_crawl_count:
            endpoint_metadata.crawl_count = EndpointMetadata.crawl_count + 1

        if fail:
            endpoint_metadata.crawl_fail_count = EndpointMetadata.crawl_fail_count + 1

        if exception:
            endpoint_metadata.crawl_exception_count = EndpointMetadata.crawl_exception_count + 1

        db.commit()

    @staticmethod
    def fuzz_finished(db:Session, em_id:int, update_fuzz_count:bool, fail:bool, exception:bool) -> None:
        """
        Updates the relevant column in the database corresponding to a system
        event related to fuzzing.

        Note that for historic reasons this function is called finished but is
        also called at startup. This method is also called once per parameter
        in the case of failures ONLY. This may result in the failure numbers
        being significantly higher than the fuzz numbers.

        Args:
            db: The session object for querying the database.
            em_id: the EndpointMetadata to update.
            update_fuzz_count: whether to increase by one the fuzz_count column.
            fail: whether to increase by one the fuzz_fail_count column.
            exception: whether to increase by one the fuzz_exception_count column.
        """
        filter = (EndpointMetadata.id == em_id)
        endpoint_metadata = db.query(EndpointMetadata).filter(filter).one()

        if update_fuzz_count:
            endpoint_metadata.fuzz_count = EndpointMetadata.fuzz_count + 1

        if fail:
            endpoint_metadata.fuzz_fail_count = EndpointMetadata.fuzz_fail_count + 1

        if exception:
            endpoint_metadata.fuzz_exception_count = EndpointMetadata.fuzz_exception_count + 1

        db.commit()

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
    metadata_id = Column(Integer, ForeignKey('endpoint_metadata.id', ondelete="CASCADE"), nullable=False, index=True)
    pwnage_id = Column(Integer, ForeignKey('pwnage.id'), index=True)

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
    def createFromDWI(cls, dwi:DatabaseWriteItem, metadata_id:Optional[int]=None, store_response:bool=False) -> RR:
        """
        Helper method for creating a `RequestResponse` object from a `models.DatabaseWriteItem`

        Args:
            dwi: Input `DatabaseWriteItem`.
            metadata_id: the EndpointMetadata.id to associate with the created RequestResponse.
            store_response: whether to store the raw response in the database.
                Due to our attempts to preserve hard-drive space we generally
                don't, with the exception of requests generated by the fuzzer
                finding a vulnerability.
        """
        exc = None
        if dwi.exception is not None:
            exc = dwi.exception.toJSON()

        resp = None
        resp_status_code=None
        if dwi.response is not None:
            if store_response:
                # This is necessary because get_state contains bytes which
                # cannot be encoded into JSON. I put my encoding logic into
                # toJSON() and this is a workaround to make use of it.
                resp = json.loads(Response(dwi.response.get_state()).toJSON()) 

            resp_status_code=dwi.response.status_code

        req = json.loads(Request(dwi.request.get_state()).toJSON())

        return cls(metadata_id=metadata_id, pretty_url=dwi.request.pretty_url,
                pretty_host=dwi.request.pretty_host, path=dwi.request.path,
                scheme=dwi.request.scheme, port=dwi.request.port,
                method=dwi.request.method,
                response_status_code=resp_status_code, exception=exc,
                request=req, response=resp)

    def to_plain(self) -> str:
        """
        Convert this database entry to a plaintext representation of request
        response. A plain text representation in this context means the
        plaintext of the request concatenated to the plaintext of the response.
        """

        if not self.request:
            return "[-] Could not generate plaintext representation of request_response."

        request = Request.fromJSON(str(self.request)).toMITM()
        request.decode(strict=False)
        req_string = assemble.assemble_request(request).decode('utf-8', errors='ignore')

        if self.response:
            response = Response.fromJSON(str(self.response)).toMITM()
            response.decode(strict=False)
            resp_string = assemble.assemble_response(response).decode('utf-8', errors='ignore')

        ret_str = str(req_string)
        if self.response:
            ret_str += "\n\n" + str(resp_string)

        return str(ret_str)

    def get_mitmproxy_request(self) -> mitmproxy.net.http.Request:
        """
        Converts this database row to a mitmproxy representation of an HTTP
        request.
        """
        try:
            req = Request.fromJSON(str(self.request)) # Old style, double JSON encoded rows.
        except json.decoder.JSONDecodeError:
            req = Request.fromJSON(json.dumps(self.request))# New style, only once JSON encoded
                #rows. TODO: don't do this.

        return req.toMITM()

# See: https://stackoverflow.com/questions/39268052/how-to-compare-enums-in-python/39268706
@total_ordering
class Severity(enum.Enum):
    GARBAGE = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    OUTRAGEOUS = 5

    def __lt__(self, other:SE) -> Any:
        if self.__class__ is other.__class__:
            return self.value < other.value

        return NotImplemented

class BugName():
    INJECTION = "Special character injection."
    PINGBACK = "Pingback received."

class BugType(enum.IntEnum):
    UNSPECIFIED = 1
    XXE = 2
    SSRF = 3
    STORED_XSS = 4
    RCE = 5
    XSS = 6

    def determine_severity(self) -> Severity:
        """
        The severity of each bug does not exist on its own, but is rather a
        reflection of our own mind. Were we to be more enligthened, we would
        dispose of all notions of vulnerability in our mind and take all bugs
        as they are in their own glory, rather than attempting to see them
        through a lens of severity.

        Returns:
            Severity: the severity of this bug.
        """

        if self.value in [BugType.XXE, BugType.SSRF, BugType.XSS, BugType.STORED_XSS]:
            return Severity.MEDIUM
        elif self.value == BugType.RCE:
            return Severity.OUTRAGEOUS
        else:
            return Severity.GARBAGE


class Pwnage(Base):
    """
    This database table stores any and all pwnage.
    """
    __tablename__ = "pwnage"

    id = Column(Integer, primary_key=True)
    request_response_id = Column(Integer, ForeignKey('request_response.id'), nullable=False, index=True)
    param_name = Column(String) 

    name = Column(String, nullable=False) 
    description = Column(String, nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    # is an integer for backward compatibility reasons.
    # 0 or NULL untriaged
    # 1 False positive
    # 2 Not false positive but no impact.
    # 3 triaged vulnerable.
    # 4 triaged vulnerable, reported.
    triage_status = Column(Integer, nullable=True, index=True) 

    fuzz_requests : RelationshipProperty = relationship("RequestResponse", foreign_keys='RequestResponse.pwnage_id') # Requests which demonstrate the bug.
