import os, json
from flask import jsonify

from . import v1profile
from .profile import get_blockchain_profile, get_profile_verifications
from .examples import EXAMPLES
from ..errors import APIError, ProfileNotFoundError, BadProfileError, \
    UsernameTakenError
from ..crossdomain import crossdomain
from ..auth import auth_required

@v1profile.route('/users/<username>')
@auth_required(exception_paths=['/v1/users/gavin', '/v1/users/example'])
@crossdomain(origin='*')
def api_user(username):
    if username == 'ryanshea-example' or username == 'example':
        return jsonify(EXAMPLES['ryanshea'])

    try:
        profile = get_blockchain_profile(username)
    except (ProfileNotFoundError, UsernameTakenError, BadProfileError) as e:
        raise APIError(str(e), status_code=404)

    #verifications = get_profile_verifications(username, profile)
    #if not verifications:
    #    verifications = {}

    return jsonify({ "profile": profile }), 200

