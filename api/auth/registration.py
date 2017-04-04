import traceback
from hashlib import sha256
from flask import render_template
from registrar.wallet import HDWallet
from registrar.crypto.utils import aes_encrypt
from ..settings import SECRET_KEY

