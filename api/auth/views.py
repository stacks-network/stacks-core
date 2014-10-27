
from flask import request, jsonify, render_template, redirect, url_for

from . import v1auth
from .core import register_user
from ..decorators import parameters_required
from ..errors import APIError

"""
@v1auth.route('/gen_developer_key/', methods=['GET'])
@parameters_required(parameters=['developer_id'])
def create_account():

	access_token = save_user(request.values['developer_id'], 'basic')

	return jsonify({'developer_id': request.values['developer_id'],
					'access_token': access_token}), 200
"""

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