import configparser
import pika

CONFIG_FILE = '/home/cli/.cli.conf'

class MissingConfigurationException(Exception):
    pass

def rabbitmq_connect() -> pika.BlockingConnection:
    """
    Connect to rabbit using data from the configuration file.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
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
