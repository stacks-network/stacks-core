from flask import jsonify

from . import v1proofs
from .proofs import profile_to_proofs
from ..crossdomain import crossdomain
from ..profile import get_db_profile, get_blockchain_profile
from ..auth import auth_required

@v1proofs.route('/users/<openname>/verifications')
@auth_required(exception_paths=['/v1/users/example/verifications'])
@crossdomain(origin='*')
def verify_profile(openname):

	try:
		refresh = int(request.args.get('refresh'))
	except:
		refresh = 0

	if refresh == 1:
		refresh = True
	else:
		refresh = False 

	profile = get_db_profile(openname)

	#for users registered outside of Onename
	if profile is None:
		profile = get_blockchain_profile(openname)

	verifications = profile_to_proofs(profile, openname, refresh)

	return jsonify({ "profile": profile, "verifications": verifications }), 200