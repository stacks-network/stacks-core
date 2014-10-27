# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import json
from functools import wraps, update_wrapper
from werkzeug.datastructures import Authorization
from flask import g, request

from . import app
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

def parameters_required(parameters):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if request.values:
                data = request.values
            elif request.data:
                try:
                    data = json.loads(request.data)
                except:
                    raise APIError('Data payload must be in JSON format', status_code=400)
            else:
                data = {}

            parameters_missing = []
            for parameter in parameters:
                if parameter not in data:
                    parameters_missing.append(parameter)
            if len(parameters_missing) > 0:
                raise APIError('Parameters missing: ' + ', '.join(parameters_missing), 400)
            return f(*args, **kwargs)
        return update_wrapper(decorated_function, f)
    return decorator



