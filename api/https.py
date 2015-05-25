from functools import wraps
from flask import request, redirect, current_app


YEAR_IN_SECS = 31536000


def redirect_to_https(status_code=301):
    """ Redirect a request to https.
    """
    if request.is_secure:
        return fn(*args, **kwargs)
    else:
        if request.url.startswith('http://'):
            new_url = request.url.replace("http://", "https://")
            return redirect(new_url, code=status_code)


def default_hsts_header():
    """ Returns the default HSTS policy.
    """
    return 'max-age={0}'.format(YEAR_IN_SECS)


def set_hsts_header(response):
    """ Adds HSTS header to each response.
    """
    if request.is_secure:
        response.headers.setdefault(
            'Strict-Transport-Security', self.hsts_header)
    return response


def https_required(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        redirect_to_https()
        return fn(*args, **kwargs)
    return decorated_view


class RequireHTTPS(object):
    """ Makes https required for a Flask app.
    """

    def __init__(self, app=None):
        self.app = app or current_app
        self.enable_https_requirement(app)

    def enable_https_requirement(self, app):
        app.before_request(redirect_to_https)
        app.after_request(set_hsts_header)
