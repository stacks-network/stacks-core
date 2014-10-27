import os, json, requests, traceback

from ..errors import APIError, ProfileNotFoundError, BadProfileError, \
    UsernameTakenError

def get_blockchain_profile(username):
    auth = ('opennamesystem', 'opennamesystem')
    BASE_URL = 'http://ons-server.halfmoonlabs.com/ons/profile?openname='

    try:
        r = requests.get(BASE_URL + username, timeout=1, verify=False, auth=auth)
    except requests.exceptions.ConnectionError:
        raise ProfileNotFoundError("User doesn't seem to exist.")
    except requests.exceptions.Timeout:
        raise ProfileNotFoundError("User doesn't seem to exist.")

    if r.status_code == 404:
        raise ProfileNotFoundError("User not found.")
    else:
        try:
            profile = json.loads(r.text)
        except ValueError:
            raise BadProfileError("User data not properly formatted.")

    if not profile:
        raise BadProfileError("User profile is empty.")

    if 'message' in profile and not ('name' in profile or 'v' in profile):
        raise UsernameTakenError(profile['message'])

    return profile

def get_profile_verifications(username, profile):
    if username == 'fredwilson':
        data = {}
        return data

    url = "http://proofcheck.halfmoonlabs.com/proofcheck/verifications?username=" + username
    
    try:
        r = requests.get(url, timeout=1, verify=False)
    except requests.exceptions.ConnectionError:
        traceback.print_exc()
        return None
    except requests.exceptions.Timeout:
        traceback.print_exc()
        return None

    try:
        data = r.json()
    except ValueError:
        traceback.print_exc()
        return None

    if type(data) is not dict:
        return None

    try:
        facebook_proof_url = profile.get('facebook', {}).get('proof', {}).get('url')
        facebook_username = profile.get('facebook', {}).get('username')
    except:
        data['facebook'] = False
    else:
        if facebook_proof_url and facebook_username:
            if facebook_username not in facebook_proof_url:
                data['facebook'] = False
            else:
                data['facebook'] = True

    try:
        twitter_proof_url = profile.get('twitter', {}).get('proof', {}).get('url')
        twitter_username = profile.get('twitter', {}).get('username')
    except:
        data['twitter'] = False
    else:
        if twitter_proof_url and twitter_username and twitter_username not in twitter_proof_url:
            data['twitter'] = False

    return data