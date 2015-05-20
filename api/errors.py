# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import json
import traceback
from flask import render_template, jsonify, request
from . import app
from .utils import camelcase_to_snakecase


class APIError(Exception):
    status_code = 500
    message = "Internal server error"

    def __init__(self, message=None, status_code=None, payload=None):
        Exception.__init__(self)
        if message:
            self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        d = dict(self.payload or ())
        d['message'] = self.message
        d['type'] = camelcase_to_snakecase(
            self.__class__.__name__.replace('Error', ''))
        return d

    def __str__(self):
        return self.message


# API error handler
@app.errorhandler(APIError)
def general_api_error_handler(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


# 404 Error handler
@app.errorhandler(404)
def resource_not_found(e):
    if len(request.path) > 1 and request.path[1] == 'v':
        return jsonify({'error': 'Resource not found'}), 404
    else:
        return render_template('error.html', status_code=404,
                               error_message="Resource not found"), 404


# 403 Error handler
@app.errorhandler(403)
def unauthorized_access(e):
    return jsonify({'error': 'Unauthorized access'}), 403


# 500 Error handler
@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


# 500 Error handler
@app.errorhandler(Exception)
def exception_error(e):
    traceback.print_exc()
    return jsonify({'error': 'Internal server error'}), 500


class UnauthorizedAccessError(APIError):
    status_code = 403
    message = ("Authentication credentials are required to complete this "
               "request. Make sure to sign up for an API account and provide "
               "your app ID and app secret when making requests.")


class InvalidProfileDataError(APIError):
    status_code = 502
    message = ("A valid JSON object has not been found. The data is "
               "likely malformed, but if you check another source for the "
               "data and it seems there is nothing wrong with it, please "
               "report this to support@onename.com, as there might have been "
               "an error with the way the data was handled.")
