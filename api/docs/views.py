# -*- coding: utf-8 -*-

from flask import Blueprint, render_template, redirect, url_for

docs = Blueprint('docs', __name__, url_prefix='/docs')


@docs.route('/', defaults={'path': ''})
@docs.route('/<path:path>')
def docs_root(path):
    return render_template('docs.html')
