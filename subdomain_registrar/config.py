import os
from blockstack_client import config

SUBDOMAIN_NAME_PATTERN = r'([a-z0-9\-_+]{{{},{}}})$'.format(3, 36)

def get_core_auth():
    config_file = os.environ.get(
        "BLOCKSTACK_CLIENT_CONFIG", os.path.expanduser("~/.blockstack/client.ini"))
    auth = config.get_config(config_file)['api_password']
    assert auth

    return auth

def get_core_api_endpoint():
    return 'http://localhost:6270', get_core_auth()

def get_tx_frequency():
    """ Returns transaction frequency of subdomain registrations in seconds """
    return 60

def max_entries_per_zonefile():
    """ Maximum entries you will try to pack in a zonefile, actual maximum may be lower
        since zonefiles can only store 4kb data """
    return 100

def get_logfile():
    path = os.path.expanduser("~/.blockstack_subdomains/subdomain_registrar.log")
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    return path

def get_subdomain_registrar_db_path():
    return os.path.expanduser("~/.blockstack_subdomains/registrar.db")

def get_lockfile():
    return os.path.expanduser("~/.blockstack_subdomains/registrar.pid")

def get_api_bind_address():
    return "localhost"

def get_api_bind_port():
    return 7103


