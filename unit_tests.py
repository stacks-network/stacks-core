import json
import unittest
import requests
import argparse
from test import test_support
from binascii import hexlify
from utilitybelt import dev_urandom_entropy
import api
from requests.auth import _basic_auth_str as basic_auth

APP_ID = 'ab67b365c7570f1916cafec5c536fdec'
APP_SECRET = 'a4a0dbde0737e7dd44c5b1b90de42829c1d843b9bb97aa61f053005e545f73fd'
BASE_URL = 'http://localhost:5000'
API_VERSION = '1'

app = api.app.test_client()

# if the above app_id is not in the local DB, uncomment these lines
#from api.auth.registration import register_user 
#register_user('test@domain.com', app_id=APP_ID, app_secret=APP_SECRET, email_user=False)

def random_username():
    return hexlify(dev_urandom_entropy(16))


def build_url(pathname):
    return '/v' + API_VERSION + pathname


def test_get_request(cls, endpoint, headers={}, status_code=200):
    resp = app.get(endpoint, headers=headers)
    data = json.loads(resp.data)
    cls.assertTrue(isinstance(data, dict))
    if not resp.status_code == status_code:
        print data
    cls.assertTrue(resp.status_code == status_code)
    return data


def test_post_request(cls, endpoint, payload, headers={}, status_code=200):
    resp = app.post(endpoint, data=json.dumps(payload), headers=headers)
    data = json.loads(resp.data)
    cls.assertTrue(isinstance(data, dict))
    cls.assertTrue(resp.status_code == status_code)
    return data


def check_data(cls, data, required_keys=[], banned_keys=[]):
    for k in required_keys:
        cls.assertTrue(k in data)
        for subkey in required_keys[k]:
            cls.assertTrue(subkey in data[k])
    for k in banned_keys:
        if len(banned_keys[k]) is 0:
            cls.assertTrue(k not in data)
        else:
            cls.assertTrue(k in data)
            for subkey in banned_keys[k]:
                cls.assertTrue(subkey not in data[k])


class LookupUsersTest(unittest.TestCase):
    def setUp(self):
        self.headers = {'Authorization': basic_auth(APP_ID, APP_SECRET)}
        self.required_subkeys = ['profile', 'verifications']
        self.banned_subkeys = ['error']

    def tearDown(self):
        pass

    def build_url(self, usernames):
        return build_url('/users/' + ','.join(usernames))

    def required_keys(self, usernames):
        keys = {}
        for username in usernames:
            keys[username] = self.required_subkeys
        return keys

    def banned_keys(self, usernames):
        keys = {}
        for username in usernames:
            keys[username] = self.banned_subkeys
        return keys

    def test_unprotected_demo_user_lookup(self):
        usernames = ['fredwilson']
        data = test_get_request(self, self.build_url(usernames),
                                headers=self.headers, status_code=200)
        check_data(self, data, required_keys=self.required_keys(usernames),
                   banned_keys=self.banned_keys(usernames))

    def test_user_lookup_without_auth(self):
        usernames = ['naval']
        data = test_get_request(self, self.build_url(usernames),
                                headers={}, status_code=401)
        check_data(self, data, required_keys={'error': ['message', 'type']},
                   banned_keys={'naval': []})

    def test_user_lookup_with_auth(self):
        usernames = ['naval']
        data = test_get_request(self, self.build_url(usernames),
                                headers=self.headers, status_code=200)
        check_data(self, data, required_keys=self.required_keys(usernames),
                   banned_keys=self.banned_keys(usernames))

    def test_user_lookup_with_multiple_users(self):
        usernames = ['fredwilson', 'naval', 'albertwenger']
        data = test_get_request(self, self.build_url(usernames),
                                headers=self.headers, status_code=200)
        check_data(self, data, required_keys=self.required_keys(usernames),
                   banned_keys=self.banned_keys(usernames))


class UserbaseTest(unittest.TestCase):
    def setUp(self):
        self.headers = {'Authorization': basic_auth(APP_ID, APP_SECRET)}

    def tearDown(self):
        pass

    def test_userbase_lookup(self):
        required_keys = {
            'stats': ['registrations'],
            'usernames': [],
            'profiles': []
        }
        data = test_get_request(self, build_url('/users'),
                                headers=self.headers, status_code=200)
        check_data(self, data, required_keys=required_keys)

    def test_recent_userbase_lookup(self):
        required_keys = {'usernames': []}
        data = test_get_request(self, build_url('/users?recent_blocks=100'),
                                headers=self.headers, status_code=200)
        check_data(self, data, required_keys=required_keys)


class SearchUsersTest(unittest.TestCase):
    def setUp(self):
        self.headers = {'Authorization': basic_auth(APP_ID, APP_SECRET)}
        self.required_keys = {'results': []}

    def tearDown(self):
        pass

    def test_simple_search_query(self):
        query = 'wenger'
        data = test_get_request(self, build_url('/search?query=' + query),
                                headers=self.headers)
        check_data(self, data, required_keys=self.required_keys)


class LookupUnspentsTest(unittest.TestCase):
    def setUp(self):
        self.headers = {'Authorization': basic_auth(APP_ID, APP_SECRET)}
        self.required_keys = {'unspents': []}

    def tearDown(self):
        pass

    def build_url(self, address):
        return build_url('/addresses/' + address + '/unspents')

    def test_address_lookup(self):
        address = 'NBSffD6N6sABDxNooLZxL26jwGetiFHN6H'
        data = test_get_request(self, self.build_url(address),
                                headers=self.headers)
        check_data(self, data, required_keys=self.required_keys)


class LookupNamesOwnedTest(unittest.TestCase):
    def setUp(self):
        self.headers = {'Authorization': basic_auth(APP_ID, APP_SECRET)}
        self.required_keys = {'names': []}

    def tearDown(self):
        pass

    def build_url(self, address):
        return build_url('/addresses/' + address + '/names')

    def test_address_lookup(self):
        address = 'NBSffD6N6sABDxNooLZxL26jwGetiFHN6H'
        data = test_get_request(self, self.build_url(address),
                                headers=self.headers)
        check_data(self, data, required_keys=self.required_keys)


class RegisterUserTest(unittest.TestCase):
    def setUp(self):
        self.headers = {
            'Authorization': basic_auth(APP_ID, APP_SECRET),
            'Content-type': 'application/json'
        }
        self.required_keys = {'status': []}

    def tearDown(self):
        pass

    def test_user_registration(self):
        payload = dict(
            recipient_address='Mx73vJcnF4Xq7AawfePRKzYCoGivw87BmY',
            passname=random_username(),
            passcard={'name': {'formatted': 'John Doe'}}
        )
        data = test_post_request(self, build_url('/users'), payload,
                                 headers=self.headers)
        check_data(self, data, required_keys=self.required_keys)


class BroadcastTransactionTest(unittest.TestCase):
    def setUp(self):
        self.headers = {'Authorization': basic_auth(APP_ID, APP_SECRET)}
        self.required_keys = {'error': ['message', 'type']}
        self.banned_keys = {'transaction_hash': []}

    def tearDown(self):
        pass

    def test_bogus_transaction_broadcast(self):
        signed_hex = '00710000015e98119922f0b'
        payload = {'signed_hex': signed_hex}
        data = test_post_request(self, build_url('/transactions'), payload,
                                 headers=self.headers, status_code=400)
        check_data(self, data, required_keys=self.required_keys,
                   banned_keys=self.banned_keys)



def test_main():
    test_support.run_unittest(
        LookupUsersTest,
        UserbaseTest,
        SearchUsersTest,
        LookupUnspentsTest,
        LookupNamesOwnedTest,
        RegisterUserTest,
        BroadcastTransactionTest,
    )


if __name__ == '__main__':
    test_main()
