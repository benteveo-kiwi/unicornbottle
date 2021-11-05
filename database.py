from sqlalchemy import create_engine, engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
# from sqlalchemy.orm.session import Session
from typing import Dict, Optional, Any, Union, TypeVar, Type
from unicornbottle.environment import read_configuration_file
from unicornbottle.models import Base
from urllib.parse import quote  
import configparser
import sqlalchemy

CONFIG_FILE = '/home/cli/.cli.conf'

class InvalidSchemaException(Exception):
    pass

class CantCreateSchemaException(Exception):
    pass

def get_url() -> str:
    """
    Get the configuration file and create a properly escaped connection string.
    """
    config = read_configuration_file() 
    
    db = config['database']

    return "postgresql://%s:%s@%s/%s" % (quote(db['username']),
            quote(db['password']), quote(db['hostname']),
            quote(db['database']))

def database_connect(schema : str, create:bool=False) -> Session:
    """
    Use SQLAlchemy to connect to the database. If the tables or schemas do not
    exist then they will be created.

    Args:
        schema: PostgreSQL schema name to use for all queries.
        create: Create tables in this schema if they do not exist. If you pass
            this flag and the schema is already up in the database, it crashes.

    Raises:
        InvalidSchemaException: if a non-existent schema is provided and the
            create parameter is false. 
        CantCreateSchemaException: raised if create is true but the schema
            already exists.

    Returns:
        session: the SQL alchemy session. Ultra mega warning! This object needs to be called within a `with` block.
            e.g. with database_connect(*args) as db:

        If you don't do that you'll leak database connections and it's going to be a bummer.
    """

    # Instruct the engine to use the schema for all queries.
    url = get_url()

    engine = create_engine(url).execution_options(
            schema_translate_map={None: schema}) # type:ignore

    # Create schemas and tables
    has_schema = engine.dialect.has_schema(engine, schema) 
    if has_schema:
        if create:
            raise CantCreateSchemaException("Couldn't create schema %s because it already exists." % schema)
    else:
        if create:
            engine.execute(sqlalchemy.schema.CreateSchema(schema))
            Base.metadata.create_all(bind=engine)
        else:
            raise InvalidSchemaException("Target %s does not exist" % schema)

    # Arcane incantations to satistfy Mypy.
    Sess = sessionmaker(bind=engine)
    session : Session = Sess()

    return session
