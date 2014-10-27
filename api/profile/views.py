import os, json
from flask import jsonify

from . import v1profile
from .profile import get_blockchain_profile, get_profile_verifications
from .samples import ryanshea
from ..errors import APIError, ProfileNotFoundError, BadProfileError, \
    UsernameTakenError
from ..crossdomain import crossdomain
from ..decorators import access_token_required

@v1profile.route('/openname/<username>')
@access_token_required
@crossdomain(origin='*')
def api_user(username):
    if username == 'ryanshea-example':
        return jsonify(ryanshea)

    try:
        profile = get_blockchain_profile(username)
    except (ProfileNotFoundError, UsernameTakenError, BadProfileError) as e:
        raise APIError(str(e), status_code=404)

    #verifications = get_profile_verifications(username, profile)
    #if not verifications:
    #    verifications = {}

    return jsonify({ "profile": profile }), 200

