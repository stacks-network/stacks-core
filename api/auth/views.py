from flask import request, jsonify, render_template, redirect, url_for

from . import v1auth
from ..helper import parameters_required
from ..errors import APIError
from .registration import register_user


@v1auth.route('/registered')
def registered():
    return render_template('registered.html')


@v1auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if 'email' in request.form and len(request.form['email']):
            email = request.form['email']
            try:
                user = register_user(email)
            except APIError:
                return render_template('emailtaken.html')
            return redirect(url_for('v1auth.registered'))
        else:
            return render_template('error.html', status_code=400,
                                   error_message="Unauthorized access.")

    return render_template('signup.html')
