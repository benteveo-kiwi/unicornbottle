from mitmproxy.net.http.http1 import assemble
from sqlalchemy import Column, Integer, String, JSON, ForeignKey, UniqueConstraint, Boolean
from sqlalchemy import or_, not_, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, RelationshipProperty, Query
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session
from typing import Dict, Optional, Any, Union, TypeVar, Type, List, Tuple
from unicornbottle.serializers import Request, Response, ExceptionSerializer, DatabaseWriteItem
import mitmproxy
import json

RR = TypeVar('RR', bound='RequestResponse')
Base : Any = declarative_base()

class InvalidScopeName(Exception):
    pass

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

    id = Column(Integer, primary_key=True)
    scope_id = Column(Integer, ForeignKey('scope.id'), nullable=False, index=True)
    pretty_url_like = Column(String, nullable=False, index=True)
    login_script = Column(String)
    negative = Column(Boolean, default=False)

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

    fuzz_count = Column(Integer, default=0, nullable=False)

    crawl_count = Column(Integer, default=0, nullable=False) # Successful crawl count.

    # Crawl failed due to bad HTTP status code or bad URL in general.  The idea
    # is that these kinds of failures may occur even if there are no bugs in
    # our code. E.g. a broken link may trigger this error.
    crawl_fail_count = Column(Integer, default=0, nullable=False) 

    # Crawl failed due to unhandled exception.  These generally should be
    # indicative of a failure on our end to either handle a specific scenario,
    # and should not occur in normal operations. E.g. An error with the
    # login_script may trigger this flag.
    crawl_exception_count = Column(Integer, default=0, nullable=False) 

    request_responses : RelationshipProperty = relationship("RequestResponse") 

    def __repr__(self) -> str:
        return "<EndpointMetadata %s (%s) fuzz_count:%s crawl_count:%s crawl_fail_count:%s crawl_exception_count:%s>" % (self.pretty_url,
                self.method, self.fuzz_count, self.crawl_count, self.crawl_fail_count, self.crawl_exception_count)

    @staticmethod
    def get_endpoints_by_scope(db:Session, scope_name:str, limit:int,
            max_crawl_count:int, method:Optional[str]=None,
            order_by:Optional[Column]=None) -> Query:
        """
        Returns the query object required in order to get all endpoints filtered by scope.

        Args:
            db: the db as returned by `unicornbottle.database.database_connect`
            scope_name: the scope as stored in the `Scope.name` model.
            limit: Absolute maximum number of results to return.
            max_crawl_count: exclude rows with a `crawl_count` higher than this value.
            method: filter by method if present.
            order_by: order by. If not present, will sort by crawl_count asc.
        """
        try:
            scope = db.query(Scope).filter(Scope.name == scope_name).one()
        except NoResultFound:
            raise InvalidScopeName("A scope named %s does not exist in the schema" % scope_name)

        # Join.
        join_filter = (EndpointMetadata.pretty_url.like(ScopeURL.pretty_url_like) & # type: ignore
                (ScopeURL.scope_id == scope.id) & (ScopeURL.login_script != None)) 

        rows:Query = db.query(EndpointMetadata, ScopeURL)\
                .join(ScopeURL, join_filter, isouter=True)

        # Filter.
        url_filters = []
        for scope_url in scope.urls:
            pretty_url_like = EndpointMetadata.pretty_url.like(scope_url.pretty_url_like)
            if scope_url.negative:
                url_filters.append(not_(pretty_url_like))
            else:
                url_filters.append(pretty_url_like)

        # Optional filters based on function parameters.
        if len(url_filters) > 0:
            rows = rows.filter(and_(*url_filters))

        if max_crawl_count != -1:
            rows = rows.filter(EndpointMetadata.crawl_count <= max_crawl_count)

        if method:
            rows = rows.filter(EndpointMetadata.method == method)

        # Order and Limit.
        if order_by:
            rows = rows.order_by(order_by)
        else:
            rows = rows.order_by(EndpointMetadata.crawl_count.asc())

        if limit != -1:
            rows = rows.limit(limit)

        return rows

    @staticmethod
    def get_crawl_endpoints(db:Session, scope_name:str, limit:int, max_crawl_count:int) -> List[Tuple[str, Optional[str]]]:
        """
        Gets endpoints that will be sent to the RabbitMQ queue as crawl tasks.

        Args:
            db: the db as returned by `unicornbottle.database.database_connect`
            scope_name: the scope as stored in the `Scope.name` model.
            limit: Absolute maximum number of results to return.
            max_crawl_count: exclude rows with a `crawl_count` higher than this value.
        """
        rows = EndpointMetadata.get_endpoints_by_scope(db, scope_name, limit, max_crawl_count)

        # Transform and increment crawl_count.
        urls = []
        for row in rows.all():
            endpoint_metadata = row[0]
            scope_url = row[1]

            urls.append((endpoint_metadata.pretty_url, scope_url.login_script))

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
    metadata_id = Column(Integer, ForeignKey('endpoint_metadata.id'), nullable=False, index=True)
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
            resp = Response(dwi.response.get_state()).toJSON()
            resp_status_code=dwi.response.status_code

        req = Request(dwi.request.get_state()).toJSON()
            
        return cls(pretty_url=dwi.request.pretty_url,
                pretty_host=dwi.request.pretty_host, path=dwi.request.path,
                scheme=dwi.request.scheme, port=dwi.request.port,
                method=dwi.request.method,
                response_status_code=resp_status_code,
                exception=exc,
                request=req,
                response=resp)

    def to_plain(self) -> str:
        """
        Convert this database entry to a plaintext representation of request
        response. A plain text representation in this context means the
        plaintext of the request concatenated to the plaintext of the response.
        """

        if not self.request or not self.response:
            return "[-] Could not generate plaintext representation of request_response."

        request = Request.fromJSON(str(self.request)).toMITM()

        response = Response.fromJSON(str(self.response)).toMITM()

        request.decode(strict=False)
        response.decode(strict=False)

        req_string = assemble.assemble_request(request).decode('utf-8', errors='ignore')
        resp_string = assemble.assemble_response(response).decode('utf-8', errors='ignore')

        return str(req_string + "\n\n" + resp_string)

    def get_mitmproxy_request(self) -> mitmproxy.net.http.Request:
        """
        Converts this database row to a mitmproxy representation of an HTTP
        request.
        """
        req = Request.fromJSON(self.request)

        return req.toMITM()


