# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import json
import requests

from flask import request
from functools import update_wrapper

from .errors import APIError
from . import app


def parameters_required(parameters):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if request.values:
                data = request.values
            elif request.data:
                try:
                    data = json.loads(request.data)
                except:
                    raise APIError(
                        'Data payload must be in JSON format', status_code=400)
            else:
                data = {}

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


def send_w_mailgun(subject, recipient, template):
    return requests.post(
        "https://api.mailgun.net/v2/onename.io/messages",
        auth=("api", app.config['MAILGUN_API_KEY']),
        data={
            "from": app.config['MAIL_USERNAME'],
            "to": recipient,
            "subject": subject,
            "html": template
        }
    )
