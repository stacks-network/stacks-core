import os, json
from flask import jsonify

from . import v1profile
from .profile import get_blockchain_profile,get_user_count
from ..errors import APIError, ProfileNotFoundError, BadProfileError, \
    UsernameTakenError
from ..crossdomain import crossdomain
from ..auth import auth_required

@auth_required(exception_paths=['/v1/user_count/example'])
@crossdomain(origin='*')
@v1profile.route('/user_count')
def user_count():
    user_count = get_user_count()
    
    if user_count == 0:
        raise APIError('internal server error',status_code=500)

    data = {
        'stats': {
            'registrations':user_count
            }
    }
    return jsonify(data), 200

@v1profile.route('/users/<username>')
@auth_required(exception_paths=['/v1/users/example'])
@crossdomain(origin='*')
def api_user(username):

    try:
        profile = get_blockchain_profile(username)
    except (ProfileNotFoundError, UsernameTakenError, BadProfileError) as e:
        raise APIError(str(e), status_code=404)

    return jsonify({"profile": profile}), 200