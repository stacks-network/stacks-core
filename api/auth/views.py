from flask import request, jsonify

from . import v1auth
from .rate_limit import save_user
from ..decorators import parameters_required

@v1auth.route('/gen_developer_key/', methods=['GET'])
@parameters_required(parameters=['developer_id'])
def create_account():
	""" creates a new dev. account
	"""
	access_token = save_user(request.values['developer_id'], 'basic')

	return jsonify({'developer_id': request.values['developer_id'],
					'access_token': access_token}), 200
