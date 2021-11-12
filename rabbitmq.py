from pika.adapters.blocking_connection import BlockingChannel, BlockingConnection
from unicornbottle.environment import read_configuration_file
from typing import Tuple
import pika

CRAWL_QUEUE = "crawl_tasks"
FUZZ_QUEUE = "fuzz_tasks"
PINGBACK_QUEUE = "pingbacks_received"

class MissingConfigurationException(Exception):
    pass

def rabbitmq_connect() -> pika.BlockingConnection:
    """
    Connect to rabbit using data from the configuration file.
    """
    config = read_configuration_file() 

    rabbit = config['rabbitmq']
    hostname = rabbit['hostname']
    username = rabbit['username']
    password = rabbit['password']
    
    if hostname is None or username is None or password is None:
        msg = "Could not connect to rabbit because the required configuration is missing."
        raise MissingConfigurationException(msg)

    credentials = pika.PlainCredentials(username, password)
    connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=hostname, credentials=credentials))

    return connection

def get_channel(queue_name:str) -> Tuple[BlockingConnection, BlockingChannel]:
    """
    Get the RabbitMQ channel for writing. 

    You (yes, I AM talking to you) should close the connection once you're done
    using it with conneciton.close()

    Args:
        queue_name: the name of the queue to connect to.
        
    Returns:
        (conn, channel) tuple: you MUST close the connection using connection.close()
    """
    connection = rabbitmq_connect()

    channel = connection.channel()
    channel.queue_declare(queue=queue_name, durable=True)

    return (connection, channel)
