import json
import requests
from flask import request
from functools import update_wrapper
from werkzeug.datastructures import MultiDict, CombinedMultiDict
from .errors import APIError


def get_request_data():
    args = []
    request_data = {}

    if request.data:
        try:
            request_data = json.loads(request.data)
        except ValueError:
            pass

    for d in request.args, request.form, request_data:
        if not isinstance(d, MultiDict):
            d = MultiDict(d)
        args.append(d)

    return CombinedMultiDict(args)


def parameters_required(parameters):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            data = get_request_data()

            parameters_missing = []
            for parameter in parameters:
                if parameter not in data:
                    parameters_missing.append(parameter)
            if len(parameters_missing) > 0:
                raise APIError(
                    'Parameters missing: ' + ', '.join(parameters_missing), 400
                )
            return f(*args, **kwargs)
        return update_wrapper(decorated_function, f)
    return decorator
