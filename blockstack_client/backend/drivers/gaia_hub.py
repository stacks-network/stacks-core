import requests, os
from ConfigParser import SafeConfigParser
from blockstack_client.logger import get_logger

ACCESS_TOKEN = None
ACCESS_ADDRESS = None
HUB_SERVER = None
HUB_URL_PREFIX = None

log = get_logger("blockstack-storage-driver-gaia_hub")

def storage_init(conf, **kwargs):
    config_path = conf['path']

    global ACCESS_TOKEN, ACCESS_ADDRESS, HUB_SERVER, HUB_URL_PREFIX

    if os.path.exists( config_path ):
        parser = SafeConfigParser()
        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        if parser.has_section('gaia_hub'):
            if parser.has_option('gaia_hub', 'token'):
                ACCESS_TOKEN = parser.get('gaia_hub', 'token')
            if parser.has_option('gaia_hub', 'address'):
                ACCESS_ADDRESS = parser.get('gaia_hub', 'address')
            if parser.has_option('gaia_hub', 'server'):
                HUB_SERVER = parser.get('gaia_hub', 'server')
            if parser.has_option('gaia_hub', 'url_prefix'):
                HUB_URL_PREFIX = parser.get('gaia_hub', 'url_prefix')

    return True

def handles_url( url ):
    if not HUB_URL_PREFIX:
        return False
    return url.startswith(HUB_URL_PREFIX)

def data_id_to_hex( data_id ):
    return "".join(x.encode('hex') for x in data_id)

def make_mutable_url( data_id ):
    if not HUB_URL_PREFIX:
        return None
    path = data_id_to_hex(data_id)
    url = "{}{}/{}".format(HUB_URL_PREFIX, ACCESS_ADDRESS, path)
    log.debug( "make_mutable_url: {}".format(url))
    return url

def put_mutable_handler( data_id, data_txt, **kw ):
    if not HUB_SERVER:
        return None

    url = "{}/store/{}/{}".format(
        HUB_SERVER,
        ACCESS_ADDRESS,
        data_id_to_hex( data_id ))
    headers = {
        "Authorization" : "bearer {}".format(ACCESS_TOKEN)
    }
    log.debug( "put_mutable_url: {}".format(url))

    resp = requests.post( url, headers = headers,
                          data = data_txt )
    if resp.status_code != 202:
        log.error(resp)
        msg = "Error putting to mutable storage. Tried store at {}".format(url)
        log.error(msg)
        return False

    log.debug(resp)
    resp_obj = resp.json()

    if 'publicURL' not in resp_obj:
        log.error("Expecting publicURL in JSON response")
        return False

    elif resp_obj['publicURL'] != make_mutable_url(data_id):
        msg = "Unexpected publicURL. Expected '{}', Actual '{}'".format(
            make_mutable_url(data_id), resp_obj['publicURL'])
        log.error(msg)
        return False

    return resp_obj['publicURL']

def get_mutable_handler( data_url, **kw):
    if not HUB_URL_PREFIX:
        return None
    log.debug("get_mutable: {}".format(data_url))
    resp = requests.get( data_url )
    if resp.status_code != 200:
        log.error(resp)
        msg = "Error getting from mutable storage. Tried store at {}".format(data_url)
        log.error(msg)
        raise Exception(msg)
    return resp.content

def get_classes():
    return ['read_public', 'write_private']
