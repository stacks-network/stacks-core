# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2016 Halfmoon Labs, Inc.
    ~~~~~
"""

import json
import traceback
import requests
import ssl
import re

from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout
from flask import request, jsonify
from flask_crossdomain import crossdomain

from basicrpc import Proxy
from pybitcoin import get_unspents, BlockcypherClient
from pybitcoin.rpc import BitcoindClient
from pybitcoin import is_b58check_address, BitcoinPrivateKey

from registrar.wallet import HDWallet
from registrar.crypto import aes_decrypt, get_address_from_pubkey
from registrar.utils import get_hash
from registrar.utils import pretty_print as pprint
from registrar.config import DEFAULT_CHILD_ADDRESSES

from . import app
from .errors import InvalidProfileDataError, UsernameTakenError, \
    InternalProcessingError, ResolverConnectionError, \
    BroadcastTransactionError, DatabaseLookupError, InternalSSLError, \
    DatabaseSaveError, DKIMPubkeyError, UsernameNotRegisteredError, \
    UpgradeInprogressError, InvalidProfileSize, \
    EmailTokenError, InvalidEmailError, \
    GenericError, PaymentError, InvalidAddressError

from .parameters import parameters_required
from .auth import auth_required, get_authenticated_user
from .models import Blockchainid, Email
from .dkim import dns_resolver, parse_pubkey_from_data, DKIM_RECORD_PREFIX
from .utils import sizeInvalid
from .db import db_client

from .settings import RESOLVER_URL, SEARCH_URL
from .settings import BLOCKCYPHER_TOKEN
from .settings import BLOCKSTORED_IP, BLOCKSTORED_PORT
from .settings import BITCOIND_SERVER, BITCOIND_PORT, BITCOIND_USER
from .settings import BITCOIND_PASSWD, BITCOIND_USE_HTTPS
from .settings import EMAILS_TOKEN, EMAIL_REGREX
from .settings import DEFAULT_NAMESPACE, PAYMENT_PRIVKEY
from .settings import SECRET_KEY, USE_DEFAULT_PAYMENT

bitcoind = BitcoindClient(BITCOIND_SERVER, BITCOIND_PORT, BITCOIND_USER,
                          BITCOIND_PASSWD, BITCOIND_USE_HTTPS)

from blockstore_client import client as bs_client

# start session using blockstore_client
bs_client.session(server_host=BLOCKSTORED_IP, server_port=BLOCKSTORED_PORT)


@app.route('/v1/users/<usernames>', methods=['GET'])
# @auth_required(exception_paths=['/v1/users/fredwilson'])
@crossdomain(origin='*')
def api_user(usernames):

    BASE_URL = RESOLVER_URL + '/v2/users/'

    try:
        resp = requests.get(BASE_URL + usernames, timeout=10, verify=False)
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    data = resp.json()

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


@app.route('/v1/users', methods=['POST'])
@auth_required()
@parameters_required(['username', 'recipient_address'])
@crossdomain(origin='*')
def register_user():
    REGISTRATION_MESSAGE = (
        "This profile was registered using the Onename"
        " API - https://api.onename.com")

    data = json.loads(request.data)

    username = data['username']

    profile_lookup = api_user(username)

    if 'error' in profile_lookup.data and profile_lookup.status_code == 200:

        if 'profile' in data:
            profile = data['profile']
        else:
            profile = {
                'status': 'registered',
                'message': REGISTRATION_MESSAGE
            }
    else:
        raise UsernameTakenError()

    if sizeInvalid(profile):
        raise InvalidProfileSize()

    if not is_b58check_address(str(data['recipient_address'])):
        raise InvalidAddressError(data['recipient_address'])

    matching_profiles = Blockchainid.objects(username=username)

    if len(matching_profiles):
        """ Someone else already tried registering this name
            but the username is not yet registered on the blockchain.
            Don't tell the client that someone else's request is processing.
        """
        pass
    else:
        new_entry = Blockchainid(username=username, profile=json.dumps(profile),
                            transfer_address=data['recipient_address'])
        try:
            new_entry.save()
        except Exception as e:
            raise DatabaseSaveError()

    resp = {'status': 'success'}

    return jsonify(resp), 200


@app.route('/v1/users/<username>/update', methods=['POST'])
@auth_required()
@parameters_required(['profile', 'owner_pubkey'])
@crossdomain(origin='*')
def update_user(username):

    reply = {}

    try:
        user = get_authenticated_user(request.authorization)
    except Exception as e:
        raise GenericError(str(e))

    try:
        hex_privkey = aes_decrypt(user.encrypted_privkey, SECRET_KEY)
    except Exception as e:
        raise GenericError(str(e))

    wallet = HDWallet(hex_privkey)
    data = json.loads(request.data)

    fqu = username + "." + DEFAULT_NAMESPACE
    profile = data['profile']
    profile_hash = get_hash(profile)
    owner_pubkey = data['owner_pubkey']

    try:
        blockchain_record = bs_client.get_name_blockchain_record(fqu)
    except Exception as e:
        raise GenericError(str(e))

    if 'value_hash' not in blockchain_record:
        raise GenericError("Not yet registered %s" % fqu)

    owner_address = blockchain_record['address']

    check_address = get_address_from_pubkey(str(owner_pubkey))

    if check_address != owner_address:
        raise GenericError("Given pubkey/address doesn't own this name.")

    if USE_DEFAULT_PAYMENT and PAYMENT_PRIVKEY is not None:

        payment_privkey = BitcoinPrivateKey(PAYMENT_PRIVKEY)
        payment_privkey = payment_privkey.to_hex()
    else:
        pubkey, payment_privkey = wallet.get_next_keypair()

        if payment_privkey is None:
            raise PaymentError(addresses=wallet.get_keypairs(DEFAULT_CHILD_ADDRESSES))

    resp = {}

    try:
        resp = bs_client.update_subsidized(fqu, profile_hash,
                                           public_key=owner_pubkey,
                                           subsidy_key=payment_privkey)
    except Exception as e:
        reply['error'] = str(e)
        return jsonify(reply), 200

    if 'subsidized_tx' in resp:
        reply['unsigned_tx'] = resp['subsidized_tx']
    else:
        if 'error' in resp:
            reply['error'] = resp['error']
        else:
            reply['error'] = resp

    return jsonify(reply), 200


@app.route('/v1/users/<username>/transfer', methods=['POST'])
@auth_required()
@parameters_required(['transfer_address', 'owner_pubkey'])
@crossdomain(origin='*')
def transfer_user(username):

    reply = {}

    try:
        user = get_authenticated_user(request.authorization)
    except Exception as e:
        raise GenericError(str(e))

    try:
        hex_privkey = aes_decrypt(user.encrypted_privkey, SECRET_KEY)
    except Exception as e:
        raise GenericError(str(e))

    wallet = HDWallet(hex_privkey)
    data = json.loads(request.data)

    fqu = username + "." + DEFAULT_NAMESPACE
    transfer_address = data['transfer_address']
    owner_pubkey = data['owner_pubkey']

    try:
        blockchain_record = bs_client.get_name_blockchain_record(fqu)
    except Exception as e:
        raise GenericError(str(e))

    if 'value_hash' not in blockchain_record:
        raise GenericError("Not yet registered %s" % fqu)

    owner_address = blockchain_record['address']

    check_address = get_address_from_pubkey(str(owner_pubkey))

    if check_address != owner_address:
        raise GenericError("Given pubkey/address doesn't own this name.")

    if not is_b58check_address(transfer_address):
        raise InvalidAddressError(transfer_address)

    if USE_DEFAULT_PAYMENT and PAYMENT_PRIVKEY is not None:

        payment_privkey = BitcoinPrivateKey(PAYMENT_PRIVKEY)
        payment_privkey = payment_privkey.to_hex()
    else:
        pubkey, payment_privkey = wallet.get_next_keypair()

        if payment_privkey is None:
            raise PaymentError(addresses=wallet.get_keypairs(DEFAULT_CHILD_ADDRESSES))

    resp = {}

    try:
        resp = bs_client.transfer_subsidized(fqu, transfer_address,
                                             keep_data=True,
                                             public_key=owner_pubkey,
                                             subsidy_key=payment_privkey)
    except Exception as e:
        reply['error'] = str(e)
        return jsonify(reply), 200

    if 'subsidized_tx' in resp:
        reply['unsigned_tx'] = resp['subsidized_tx']
    else:
        if 'error' in resp:
            reply['error'] = resp['error']
        else:
            reply['error'] = resp

    return jsonify(reply), 200


@app.route('/v1/search', methods=['GET'])
#@auth_required(exception_queries=['fredwilson', 'wenger'])
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


@app.route('/v1/transactions', methods=['POST'])
@auth_required()
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


@app.route('/v1/addresses/<address>/unspents', methods=['GET'])
@auth_required(exception_paths=[
    '/v1/addresses/19bXfGsGEXewR6TyAV3b89cSHBtFFewXt6/unspents'])
@crossdomain(origin='*')
def get_address_unspents(address):

    client = BlockcypherClient(api_key=BLOCKCYPHER_TOKEN)
    unspent_outputs = get_unspents(address, blockchain_client=client)

    resp = {'unspents': unspent_outputs}

    return jsonify(resp), 200


@app.route('/v1/addresses/<addresses>/names', methods=['GET'])
@auth_required(exception_paths=[
    '/v1/addresses/1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP/names'])
@crossdomain(origin='*')
def get_address_names(addresses):

    resp = {}
    names_owned = []
    results = []

    addresses = addresses.split(',')

    for address in addresses:

        try:
            is_b58check_address(str(address))
        except:
            continue

        bs_client = Proxy(BLOCKSTORED_IP, BLOCKSTORED_PORT)

        try:
            resp = bs_client.get_names_owned_by_address(address)
            names_owned = resp[0]
        except:
            pass

        data = {'address': address,
                'names': names_owned}
        results.append(data)

    resp = {'results': results}

    return jsonify(resp), 200


@app.route('/v1/users', methods=['GET'])
#@auth_required()
@crossdomain(origin='*')
def get_all_users():

    BASE_URL = RESOLVER_URL + '/v2/namespace'

    try:
        resp = requests.get(BASE_URL, timeout=10, verify=False)
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    data = resp.json()

    return jsonify(data), 200


@app.route('/v1/stats/users', methods=['GET'])
@crossdomain(origin='*')
def get_user_stats():

    data = get_all_users().data
    data = json.loads(data)

    resp = {'stats': data['stats']}

    return jsonify(resp), 200


@app.route('/v1/domains/<domain>/dkim', methods=['GET'])
@auth_required(exception_paths=['/v1/domains/onename.com/dkim'])
@crossdomain(origin='*')
def get_dkim_pubkey(domain):

    domain = DKIM_RECORD_PREFIX + domain
    data = dns_resolver(domain)
    public_key_data = parse_pubkey_from_data(data)

    if public_key_data['public_key'] is None:
        raise DKIMPubkeyError()

    resp = public_key_data

    return jsonify(resp), 200


@app.route('/v1/emails', methods=['GET'])
@crossdomain(origin='*')
def get_emails_info():

    resp = {}
    resp["message"] = "This endpoint is for emails re blockstore critical updates. Use the given token for submitting new emails"

    resp["token"] = EMAILS_TOKEN

    return jsonify(resp), 200


@app.route('/v1/emails', methods=['POST'])
@parameters_required(['email', 'token'])
@crossdomain(origin='*')
def submit_emails():

    resp = {}

    data = json.loads(request.data)

    token = data['token']
    email = data['email']
    email_list = "default"

    try:
        email_list = data['list']
    except:
        pass

    if token != EMAILS_TOKEN:
        raise EmailTokenError

    if not re.match(EMAIL_REGREX, email):
        raise InvalidEmailError

    check_entry = db_client['email'].find_one({'address': email})

    if check_entry is not None:
        resp['message'] = "Email already exists"
        resp['status'] = 'success'
        return jsonify(resp), 200

    new_entry = Email(address=email, email_list=email_list)

    try:
        new_entry.save()
        resp['status'] = 'success'
    except Exception as e:
        raise DatabaseSaveError()

    return jsonify(resp), 200
