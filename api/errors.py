import json
from flask import render_template, jsonify

from . import app

class APIError(Exception):
    status_code = 500

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

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
    return jsonify({ 'error': 'Resource not found' }), 404

# 403 Error handler
@app.errorhandler(403)
def unauthorized_access(e):
    return jsonify({ 'error': 'Unauthorized access' }), 404

# 500 Error handler
@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({ 'error': 'Internal server error' }), 404

