from unicornbottle.environment import read_configuration_file
import pika

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
