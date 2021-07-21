from sqlalchemy import create_engine, engine
from sqlalchemy import Column, Integer, String, JSON
from typing import Any
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from urllib.parse import quote  
import configparser
import sqlalchemy

Base : Any = declarative_base()

CONFIG_FILE = '/home/cli/.cli.conf'

class InvalidSchemaException(Exception):
    pass

class RequestResponse(Base):
    """
    This table contains the requests sent through the proxy and, if there are
    any, also information regarding either the response or the error. These map
    almost 1:1 to attributes that are present in the `mitmproxy` api
    documentation, so if you need more information regarding any of the fields
    you can also find information there.

    The following columns are not part of that api:

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
    error = Column(JSON)
    request = Column(JSON)
    response = Column(JSON)
    fuzz_count = Column(Integer)
    crawl_count = Column(Integer)

def get_url() -> str:
    """
    Get the configuration file and create a properly escaped connection string.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    db = config['database']

    return "postgresql://%s:%s@%s/%s" % (quote(db['username']),
            quote(db['password']), quote(db['hostname']),
            quote(db['database']))

def database_connect(schema : str, create:bool) -> sessionmaker:
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

    session = sessionmaker(bind=engine)

    return session
