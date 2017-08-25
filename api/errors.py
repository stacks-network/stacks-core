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


class GenericError(APIError):
    status_code = 403
    message = "Internal server error"

    def __init__(self, error_message):
        super(self.__class__, self).__init__()
        self.message = error_message


class PaymentError(APIError):
    status_code = 402
    message = "Payment addresses are either under funded or have pending transactions: "

    def __init__(self, addresses):
        super(self.__class__, self).__init__()
        self.message += str(addresses)


class InvalidAddressError(APIError):
    status_code = 403
    message = "Given address is not a valid cryptocurrency address: "

    def __init__(self, address):
        super(self.__class__, self).__init__()
        self.message += str(address)


class MethodNotAllowedError(APIError):
    status_code = 405
    message = ("The HTTP method used in this request is not allowed by this "
               "endpoint. Check the API documentation to see which ones are "
               "supported.")


class InvalidCredentialsError(APIError):
    status_code = 401
    message = ("Invalid API credential provided. Make sure your app ID and "
               "app secret are correct.")


class MissingCredentialsError(APIError):
    status_code = 401
    message = ("Authentication credentials are required to complete this "
               "request. Make sure to sign up for an API account and provide "
               "your app ID and app secret when making requests.")


class AccountRegistrationError(APIError):
    status_code = 500
    message = ("Could not register API account. It is possible there already "
               "exists an account with the email address provided.")


class InvalidProfileDataError(APIError):
    status_code = 502
    message = ("A valid JSON object has not been found. The data is "
               "likely malformed, but if you check another source for the "
               "data and it seems there is nothing wrong with it, please "
               "report this to support@onename.com, as there might have been "
               "an error with the way the data was handled.")


class InvalidZoneFileTypeError(APIError):
    status_code = 401
    message = ("The zone file supplied must be a string.")


class InvalidZoneFileSizeError(APIError):
    status_code = 401
    message = ("Profile data is invalid, because it exceeds maximum size.")


class UsernameTakenError(APIError):
    status_code = 403
    message = ("There already exists a profile with the username provided.")


class UsernameTakenError(APIError):
    status_code = 403
    message = ("There already exists a profile with the username provided.")


class UsernameNotRegisteredError(APIError):
    status_code = 404
    message = ("This username is not registered.")


class DatabaseSaveError(APIError):
    status_code = 500
    message = ("There was a problem saving to the database. Please report "
               "this error to support@onename.com.")


class DatabaseLookupError(APIError):
    status_code = 500
    message = ("There was a problem performing a lookup in the database. "
               "Please report this error to support@onename.com.")


class InternalProcessingError(APIError):
    status_code = 500
    message = ("There was a problem processing the request. Please report "
               "this error to support@onename.com.")


class InternalSSLError(APIError):
    status_code = 500
    message = ("There was a problem processing the request with an internal "
               "SSL error. Please report this error to support@onename.com.")


class ResolverConnectionError(APIError):
    status_code = 500
    message = ("There was a problem processing the request. It seems that the "
               "name system resolver could not be reached. Please report "
               "this error to support@onename.com.")


class DKIMPubkeyError(APIError):
    status_code = 404
    message = ("Public key record for domain not found")


class EmailTokenError(APIError):
    status_code = 401
    message = ("Missing or invalid token. A valid token is required for "
               "submitting emails")


class InvalidEmailError(APIError):
    status_code = 400
    message = ("Invalid email address.")


class PageNotFoundError(APIError):
    status_code = 400
    message = ("Page not found.")


class UpgradeInprogressError(APIError):
    status_code = 403
    message = ("This end-point is currently being upgraded and is temporarily unavailable")


class BroadcastTransactionError(APIError):
    status_code = 400
    message = ("There was a problem broadcasting the transaction to the "
               "network. Make sure that your transaction is well-formed that "
               "it has sufficient valid unspent outputs referenced as inputs "
               "to the transaction.")

    def __init__(self, network_error_message):
        super(self.__class__, self).__init__()
        message_extension = " Error message received from the network: %s" % (
            network_error_message)
        self.message = self.message + message_extension


# 404 Error handler
@app.errorhandler(404)
def resource_not_found(e):
    if len(request.path) > 1 and request.path[1] == 'v':
        error = PageNotFoundError()
        response = jsonify({'error': error.to_dict()})
        response.status_code = 400
        return response
    else:
        return render_template('error.html', status_code=404,
                               error_message="Resource not found"), 404


# 405 Error Handler
@app.errorhandler(405)
def method_not_allowed(e):
    error = MethodNotAllowedError()
    response = jsonify({'error': error.to_dict()})
    response.status_code = 405
    return response


# API error handler
@app.errorhandler(APIError)
def general_api_error_handler(error):
    response = jsonify({'error': error.to_dict()})
    response.status_code = error.status_code
    return response


# 500 Error handler
@app.errorhandler(Exception)
@app.errorhandler(500)
def exception_error(e):
    traceback.print_exc()
    error = InternalProcessingError()
    response = jsonify({'error': error.to_dict()})
    response.status_code = 500
    return response
