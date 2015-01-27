from flask import request, jsonify, render_template, redirect, url_for

from . import v1auth
from ..parameters import parameters_required
from ..errors import APIError
from .registration import register_user


@v1auth.route('/registered')
def registered():
    return render_template('registered.html')


@v1auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if request.form and 'email' in request.form:
            email = request.form['email']
            try:
                user = register_user(email)
            except APIError:
                return "user already exists"
            return redirect(url_for('v1auth.registered'))
        else:
            return "something went wrong"

    return render_template('signup.html')
