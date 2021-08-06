from sqlalchemy import create_engine, engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from typing import Dict, Optional, Any, Union, TypeVar, Type
from unicornbottle.environment import read_configuration_file
from unicornbottle.models import Base
from urllib.parse import quote  
import configparser
import sqlalchemy

CONFIG_FILE = '/home/cli/.cli.conf'

class InvalidSchemaException(Exception):
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
