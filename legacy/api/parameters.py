#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack Core
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack Core.

    Blockstack Core is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack Core is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack Core. If not, see <http://www.gnu.org/licenses/>.
"""

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
