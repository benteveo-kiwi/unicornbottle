from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

from unicornbottle import database
from unicornbottle import database_models
import logging

logger = logging.getLogger(__name__)

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config
config.set_main_option('sqlalchemy.url', database.get_url())

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = database_models.Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    raise Exception("I don't know what this is so it's not supported.")
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # TODO: detect all schema names.
        # WIP obtained from here: https://stackoverflow.com/questions/21109218/alembic-support-for-multiple-postgres-schemas/44929128#44929128
        all_schema_names = ["d8aab38c-7d05-42b8-8a0e-f96298288051"]
        for tenant_schema_name in all_schema_names:
            conn = connection.execution_options(schema_translate_map={None: tenant_schema_name})
            conn.execute('SET search_path TO "{schema}"'.format(schema=tenant_schema_name))

            print("Migrating tenant schema %s" % tenant_schema_name)

            context.configure(
                connection=conn, target_metadata=target_metadata, version_table_schema=tenant_schema_name
            )

            with context.begin_transaction():
                context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
