# -*- coding: utf-8 -*-
"""
    Blockstack API
    ~~~~~
"""

import re
import ssl
import json
import traceback
import requests

from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout
from flask import request, jsonify
from flask_crossdomain import crossdomain

from pybitcoin import get_unspents, BlockcypherClient
from pybitcoin.rpc import BitcoindClient
from pybitcoin import is_b58check_address, BitcoinPrivateKey

from . import app
from .errors import (
    InvalidProfileDataError, UsernameTakenError,
    InternalProcessingError, ResolverConnectionError,
    BroadcastTransactionError, DatabaseLookupError, InternalSSLError,
    DatabaseSaveError, DKIMPubkeyError, UsernameNotRegisteredError,
    UpgradeInprogressError, InvalidZoneFileSizeError,
    EmailTokenError, InvalidEmailError,
    GenericError, PaymentError, InvalidAddressError,
    InvalidZoneFileTypeError
)

from .parameters import parameters_required
from .dkim import dns_resolver, parse_pubkey_from_data, DKIM_RECORD_PREFIX
from .utils import zone_file_is_too_big
from .s3 import s3_upload_file
from .resolver.server import get_users

from .settings import (
    SEARCH_URL, BLOCKSTACKD_IP, BLOCKSTACKD_PORT,
    BITCOIND_SERVER, BITCOIND_PORT, BITCOIND_USER,
    BITCOIND_PASSWD, BITCOIND_USE_HTTPS,
    DEFAULT_NAMESPACE
)

bitcoind = BitcoindClient(BITCOIND_SERVER, BITCOIND_PORT, BITCOIND_USER,
                          BITCOIND_PASSWD, BITCOIND_USE_HTTPS)

from blockstack_client import client as bs_client

# start session using blockstore_client
bs_client.session(server_host=BLOCKSTACKD_IP, server_port=BLOCKSTACKD_PORT)


@app.route('/v3/users/<usernames>', methods=['GET'], strict_slashes=False)
@crossdomain(origin='*')
def api_get_users(usernames):

    data = get_users(usernames)

    usernames = usernames.split(',')

    if len(usernames) is 1:
        username = usernames[0]
        if 'error' in data:
            del data['error']
            error = UsernameNotRegisteredError('')
            data[username] = {
                'error': error.to_dict()
            }
            return jsonify(data), 200

    for username in usernames:
        if username not in data:
            error = UsernameNotRegisteredError('')
            data[username] = {
                'error': error.to_dict()
            }

        try:
            json.loads(json.dumps(data[username]))
        except:
            error = InvalidProfileDataError('')
            data[username] = {
                'error': error.to_dict()
            }

    return jsonify(data), 200


@app.route('/v3/search', methods=['GET'])
@parameters_required(parameters=['query'])
@crossdomain(origin='*')
def search_people():

    search_url = SEARCH_URL + '/search'

    name = request.values['query']

    try:
        resp = requests.get(url=search_url, params={'query': name})
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise InternalProcessingError()

    data = resp.json()
    if not ('results' in data and isinstance(data['results'], list)):
        data = {'results': []}

    return jsonify(data), 200


@app.route('/v3/transactions', methods=['POST'])
@parameters_required(['signed_hex'])
@crossdomain(origin='*')
def broadcast_tx():

    data = json.loads(request.data)
    signed_hex = data['signed_hex']

    try:
        bitcoind_response = bitcoind.sendrawtransaction(signed_hex)
    except ssl.SSLError:
        raise InternalSSLError()
    except Exception as e:
        traceback.print_exc()
        raise BroadcastTransactionError()

    if 'code' in bitcoind_response:
        raise BroadcastTransactionError(bitcoind_response['message'])

    resp = {'transaction_hash': bitcoind_response, 'status': 'success'}

    return jsonify(resp), 200


@app.route('/v3/addresses/<addresses>/names', methods=['GET'])
@crossdomain(origin='*')
def get_address_names(addresses):

    resp = {}
    results = []

    addresses = addresses.split(',')

    for address in addresses:

        data = {}
        names_owned = []

        invalid_address = False

        try:
            is_b58check_address(str(address))
        except:
            data['error'] = "Invalid address"
            invalid_address = True

        if not invalid_address:

            try:
                resp = bs_client.get_names_owned_by_address(address)
                names_owned = resp[0]
            except:
                pass

        data['address'] = address
        data['names'] = names_owned

        results.append(data)

    resp = {'results': results}

    return jsonify(resp), 200


@app.route('/v3/users', methods=['GET'])
@crossdomain(origin='*')
def get_all_users():

    BASE_URL = RESOLVER_URL + '/v2/namespace'

    try:
        resp = requests.get(BASE_URL, timeout=10, verify=False)
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    data = resp.json()

    return jsonify(data), 200


@app.route('/v3/stats/users', methods=['GET'])
@crossdomain(origin='*')
def get_user_stats():

    data = get_all_users().data
    data = json.loads(data)

    resp = {'stats': data['stats']}

    return jsonify(resp), 200


@app.route('/v3/domains/<domain>/dkim', methods=['GET'])
@crossdomain(origin='*')
def get_dkim_pubkey(domain):

    domain = DKIM_RECORD_PREFIX + domain
    data = dns_resolver(domain)
    public_key_data = parse_pubkey_from_data(data)

    if public_key_data['public_key'] is None:
        raise DKIMPubkeyError()

    resp = public_key_data

    return jsonify(resp), 200
