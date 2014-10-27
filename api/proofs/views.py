import json, traceback
from flask import jsonify, request

from . import v1proofs
from .proofs import profile_to_verifications
from ..errors import APIError
from ..decorators import parameters_required, access_token_required
from ..crossdomain import crossdomain
from ..profile import get_blockchain_profile

@v1proofs.route('/verifications', methods=['POST'])
@parameters_required(parameters=["openname"])
@crossdomain(origin='*')
def verify_profile():
	if not (request.data or request.form):
		raise APIError('A payload must be included', status_code=400)

	if request.data:
		try:
			data = json.loads(request.data)
		except ValueError:
			raise APIError('Data must be in JSON format', status_code=400)
	elif request.form:
		try:
			data = dict(request.form)
		except:
			traceback.print_exc()
			raise APIError('Invalid form data', status_code=400)

	openname = str(data["openname"][0])
	if "profile" in data:
		profile = data["profile"]
	else:
		profile = get_blockchain_profile(openname)
	
	verifications = profile_to_verifications(profile, openname)

	return jsonify({ "profile": profile, "verifications": verifications }), 200
