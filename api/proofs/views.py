import json
from flask import jsonify, request

from . import v1proofs
from .proofs import profile_to_verifications
from ..errors import APIError
from ..decorators import parameters_required

@v1proofs.route('/verifications', methods=['POST'])
@access_token_required
@parameters_required(parameters=["profile", "openname"])
@crossdomain(origin='*')
def verify_profile():
	if not request.data:
		raise APIError('A payload must be included', status_code=400)

	try:
		data = json.loads(request.data)
	except ValueError:
		raise APIError('Data must be in JSON format', status_code=400)

	profile = data["profile"]
	openname = data["openname"]
	
	verifications = profile_to_verifications(profile, openname)

	return jsonify({ "verifications": verifications }), 200
