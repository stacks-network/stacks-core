from hashlib import sha256
from functools import wraps, update_wrapper
from werkzeug.datastructures import Authorization
from flask import g, request

from .models import User
from ..errors import APIError

def authenticate_user(app_id, app_secret):
    app_secret_hash = sha256(app_secret).hexdigest()
    users = User.objects(app_id=app_id, app_secret=app_secret)
    if users and len(users) == 1:
        user = users[0]
        user.request_count = user.request_count + 1
        try:
            user.save()
        except:
            pass

        return True
    return False

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        app_id = request.values.get('app_id')
        app_secret = request.values.get('app_secret')

        if request.authorization:
            auth = request.authorization
            app_id = request.authorization.username
            app_secret = request.authorization.password
        elif app_id and app_secet:
            auth = Authorization('basic', data={'username': app_id, 'password': app_secret})
        else:
            raise APIError('API credentials missing', status_code=400)

        if not authenticate_user(app_id, app_secret):
            raise APIError('Invalid API credentials', status_code=400)

        return f(*args, **kwargs)
    return decorated_function
