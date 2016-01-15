import traceback
from hashlib import sha256
from flask import render_template
from registrar.wallet import HDWallet
from registrar.crypto.utils import aes_encrypt
from ..settings import SECRET_KEY

from .models import User
from .utils import generate_app_secret, generate_app_id
from ..mail import send_w_mailgun
from ..errors import AccountRegistrationError


def email_user_credentials(user):
    template = render_template(
        'email/registration.html', user=user, app_secret=user.app_secret)
    subject = 'Your Onename API Credentials'
    send_w_mailgun(subject, user.email.encode('utf8'), template)


def register_user(email, app_id=None, app_secret=None, email_user=True):
    if not app_id:
        app_id = generate_app_id()
    if not app_secret:
        app_secret = generate_app_secret()
    app_secret_hash = sha256(app_secret).hexdigest()

    #generate new HD wallet key
    wallet = HDWallet()
    hex_privkey = wallet.get_privkey()
    encrypted_privkey = aes_encrypt(hex_privkey, SECRET_KEY)

    user = User(
        email=email, app_id=app_id, app_secret=app_secret,
        app_secret_hash=app_secret_hash,
        encrypted_privkey=encrypted_privkey)
    try:
        user.save()
    except Exception as e:
        traceback.print_exc()
        raise AccountRegistrationError()

    if email_user:
        email_user_credentials(user)
