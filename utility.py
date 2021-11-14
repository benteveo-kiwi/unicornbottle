from unicornbottle.environment import read_configuration_file
from unicornbottle.database_models import BugType
import functools
import random
import string

def get_random_string(length:int) -> str:
    """
    Generates a random ascii lowercase string.

    Args:
        length: the length of the string.

    Returns:
        string: a string...
    """
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str

@functools.lru_cache()
def get_pingback_domain() -> str:
    """
    Gets the domain from the config file. I cache it because I want to prevent
    unnecessary file reads in the event pingback URLs need to be repeatedly
    created.
    """
    domain = read_configuration_file()['domain']['name']
    return domain

def generate_pingback_url(target_id:int, req_resp_id:int, param_name:str, bug_type:BugType) -> str:
    """
    Generate a URL which, if resolved by a system will trigger our pingback
    listener to note it down.

    It follows a standard format which is then parsed and written in the
    database as potential Pwnage.

    Args:
        target_id: the target ID as an integer. This can be obtained by
            querying the `database_models.Target` model.
        req_resp_id: the ID which will potentially cause this pingback to
            trigger.
        param_name: the param which will potentially cause this pingback to
            trigger.
        bug_type: an enum to quickly correlate the type of payload that
            triggered this response.
    """
    domain = get_pingback_domain()

    tpl = "z%s.%s.%s.%s.%s" 

    return tpl % (str(target_id), str(req_resp_id), param_name, int(bug_type), domain)
