from hashlib import sha256
from functools import wraps, update_wrapper
from werkzeug.datastructures import Authorization
from flask import g, request

from .models import User
from ..errors import MissingCredentialsError, InvalidCredentialsError


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


def auth_required(exception_paths=None, exception_queries=None):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if request.authorization:
                auth = request.authorization
                app_id = request.authorization.username
                app_secret = request.authorization.password
            elif 'app-id' in request.values and 'app-secret' in request.values:
                app_id = request.values.get('app-id')
                app_secret = request.values.get('app-secret')
                auth = Authorization(
                    'basic', data={'username': app_id, 'password': app_secret})
            else:
                raise MissingCredentialsError()

            if exception_paths and str(request.path) in exception_paths:
                pass
            elif (exception_queries and request.values.get('query')
                    and request.values.get('query') in exception_queries):
                pass
            elif not authenticate_user(app_id, app_secret):
                raise InvalidCredentialsError()

            return f(*args, **kwargs)
        return update_wrapper(decorated_function, f)
    return decorator
