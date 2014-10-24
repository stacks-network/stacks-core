# -*- coding: utf-8 -*-

from flask import Blueprint

v1 = Blueprint('v1', __name__, url_prefix='/v1')

import search
import profile
import auth
import misc