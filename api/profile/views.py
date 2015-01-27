import os
import json
from flask import jsonify

from . import v1profile
from .profile import get_blockchain_profile, get_profile_verifications
from ..errors import APIError, ProfileNotFoundError, BadProfileError, \
    UsernameTakenError
from ..crossdomain import crossdomain
from ..auth import auth_required


@v1profile.route('/users', methods=['GET'])
@crossdomain(origin='*')
def user_count():
    data = {
        'stats': {
            'registrations': 23000
        }
    }
    return jsonify(data), 200


@v1profile.route('/users/<username>')
@auth_required(exception_paths=['/v1/users/fredwilson', '/v1/users/example'])
@crossdomain(origin='*')
def api_user(username):

    try:
        profile = get_blockchain_profile(username)
    except (ProfileNotFoundError, UsernameTakenError, BadProfileError) as e:
        raise APIError(str(e), status_code=404)

    # verifications = get_profile_verifications(username, profile)
    # if not verifications:
    #    verifications = {}

    return jsonify({"profile": profile}), 200
