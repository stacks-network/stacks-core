import traceback
from hashlib import sha256
from flask import render_template

from .models import User
from .utils import generate_app_secret, generate_app_id
from ..mail import send_w_mailgun
from ..errors import APIError


def register_user(email):
    app_id = generate_app_id()
    app_secret = generate_app_secret()
    app_secret_hash = sha256(app_secret).hexdigest()
    user = User(
        email=email, app_id=app_id, app_secret=app_secret,
        app_secret_hash=app_secret_hash)
    try:
        user.save()
    except:
        traceback.print_exc()
        raise APIError('Could not register user')

    template = render_template(
        'email/registration.html', user=user, app_secret=app_secret)
    subject = 'Your Onename API Credentials'
    send_w_mailgun(subject, user.email.encode('utf8'), template)
