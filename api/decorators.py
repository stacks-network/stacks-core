# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from functools import wraps, update_wrapper
from werkzeug.datastructures import Authorization
from flask import g, request

from . import app
from .rate_limit import validate_token, decrement_quota
from .errors import APIError

"""
def after_this_request(func):
    if not hasattr(g, 'call_after_request'):
        g.call_after_request = []
    g.call_after_request.append(func)
    return func

@app.after_request
def per_request_callbacks(response):
    for func in getattr(g, 'call_after_request', ()):
        response = func(response)
    return response
"""

def access_token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        demo_tokens = ['demo-1234']
        token = request.values.get('token')
        if request.authorization:
            auth = request.authorization
            token = request.authorization.username
        elif token:
            auth = Authorization('basic', data={'username':token, 'password':''})
        else:
            raise APIError('Access token missing', status_code=400)

        if token not in demo_tokens:
            if not validate_token(token):
                raise APIError('Invalid token', status_code=400)

            if not decrement_quota(token):
                raise APIError('Quota exceeded', status_code=401)

        return f(*args, **kwargs)
    return decorated_function

def parameters_required(parameters):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            parameters_missing = []
            for parameter in parameters:
                if parameter not in request.values:
                    parameters_missing.append(parameter)
            if len(parameters_missing) > 0:
                raise APIError('Parameters missing: ' + ', '.join(parameters_missing), 400)
            return f(*args, **kwargs)
        return update_wrapper(decorated_function, f)
    return decorator
