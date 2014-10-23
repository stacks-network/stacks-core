import os, json, requests
from flask import Flask
from flask import Response, url_for, request, jsonify

from . import app
from .errors import APIError, ProfileNotFoundError, BadProfileError, \
    UsernameTakenError
from .crossdomain import crossdomain
from .decorators import access_token_required
import samples

def get_blockchain_profile(username):
    key = 'u/' + username
    BASE_URL = 'http://coinrpc.halfmoonlabs.com/namecoind/full_profile?key='

    try:
        r = requests.get(BASE_URL + key, timeout=1, verify=False)
    except requests.exceptions.ConnectionError:
        raise ProfileNotFoundError("User doesn't seem to exist.")
    except requests.exceptions.Timeout:
        raise ProfileNotFoundError("User doesn't seem to exist.")

    if r.status_code == 404:
        raise ProfileNotFoundError("User not found.")
    else:
        try:
            profile = json.loads(r.text)
        except ValueError:
            raise BadProfileError("User data not properly formatted.")

    if not profile:
        raise BadProfileError("User profile is empty.")

    if 'message' in profile and not ('name' in profile or 'v' in profile):
        raise UsernameTakenError(profile['message'])

    return profile

@app.route('/v1/openname/<username>')
@access_token_required
@crossdomain(origin='*')
def api_user(username):
    if username == 'ryanshea-example':
        return jsonify(samples.ryanshea)

    try:
        profile = get_blockchain_profile(username)
    except (ProfileNotFoundError, UsernameTakenError, BadProfileError) as e:
        raise APIError(str(e), status_code=404)

    return jsonify(profile), 200

