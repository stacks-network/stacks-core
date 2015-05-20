import json
import unittest
import requests
from test import test_support
from binascii import hexlify
from utilitybelt import dev_urandom_entropy

APP_ID = '39abc40158e78c6ae96c2a350401c56f'
APP_SECRET = 'd909fe1396accded7f7a3a449140ea5b6761605a1683d4df499fa583b406e541'
BASE_URL = 'http://localhost:5000'
API_VERSION = '1'


def random_username():
    return hexlify(dev_urandom_entropy(16))


def build_url(pathname):
    return BASE_URL + '/v' + API_VERSION + pathname


def make_get_request(cls, url, auth=None, headers={}):
    if auth:
        r = requests.get(url, auth=auth, headers=headers)
    else:
        r = requests.get(url, headers=headers)
    cls.assertTrue(isinstance(r.json(), dict))
    return r


def make_post_request(cls, url, payload, auth=None,
                      headers={'Content-type': 'application/json'}):
    if auth:
        r = requests.post(
            url, data=json.dumps(payload), auth=auth, headers=headers)
    else:
        r = requests.get(url, data=json.dumps(payload), headers=headers)
    cls.assertTrue(isinstance(r.json(), dict))
    return r


def validate_response(cls, resp, required_keys=[],
                      banned_keys=[], status_code=200):
    data = resp.json()
    cls.assertTrue(resp.status_code == status_code)
    for k in required_keys:
        cls.assertTrue(k in data)
    for k in banned_keys:
        cls.assertTrue(k not in data)


class LookupUsersTest(unittest.TestCase):
    def setUp(self):
        self.auth = (APP_ID, APP_SECRET)
        self.demo_auth = ('', '')

    def tearDown(self):
        pass

    def build_url(self, usernames):
        return build_url('/users/' + ','.join(usernames))

    def test_unprotected_demo_user_lookup(self):
        usernames = ['fredwilson']
        r = make_get_request(
            self, self.build_url(usernames), auth=self.demo_auth)
        validate_response(self, r, required_keys=usernames, status_code=200)

    def test_user_lookup_without_auth(self):
        usernames = ['naval']
        r = make_get_request(self, self.build_url(usernames))
        validate_response(self, r, banned_keys=usernames, status_code=401)

    def test_user_lookup_with_auth(self):
        usernames = ['naval']
        r = make_get_request(self, self.build_url(usernames), auth=self.auth)
        validate_response(self, r, required_keys=usernames, status_code=200)

    def test_user_lookup_with_multiple_users(self):
        usernames = ['fredwilson', 'naval', 'albertwenger']
        r = make_get_request(self, self.build_url(usernames), auth=self.auth)
        validate_response(self, r, required_keys=usernames, status_code=200)


class BroadcastTransactionTest(unittest.TestCase):
    def setUp(self):
        self.auth = (APP_ID, APP_SECRET)
        self.demo_auth = ('', '')

    def tearDown(self):
        pass

    def test_bogus_transaction_broadcast(self):
        signed_hex = '00710000015e98119922f0b'
        payload = {'signed_hex': signed_hex}
        r = make_post_request(self, build_url('/transactions'),
                              payload, auth=self.auth)
        validate_response(self, r, required_keys=['error'],
                          banned_keys=['transaction_hash'], status_code=400)


class UserbaseStatsTest(unittest.TestCase):
    def setUp(self):
        self.auth = (APP_ID, APP_SECRET)
        self.demo_auth = ('', '')

    def tearDown(self):
        pass

    def test_stats_lookup(self):
        r = make_get_request(self, build_url('/users'))
        validate_response(self, r, required_keys=['stats'], status_code=200)


class SearchUsersTest(unittest.TestCase):
    def setUp(self):
        self.auth = (APP_ID, APP_SECRET)
        self.demo_auth = ('', '')

    def tearDown(self):
        pass

    def test_simple_search_query(self):
        query = 'wenger'
        r = make_get_request(
            self, build_url('/search?query=' + query), auth=self.auth)
        validate_response(self, r, required_keys=['results'], status_code=200)


class LookupAddressTest(unittest.TestCase):
    def setUp(self):
        self.auth = (APP_ID, APP_SECRET)
        self.demo_auth = ('', '')
        self.required_keys = ['names_owned', 'unspent_outputs']

    def tearDown(self):
        pass

    def test_address_lookup(self):
        address = 'NBSffD6N6sABDxNooLZxL26jwGetiFHN6H'
        r = make_get_request(
            self, build_url('/addresses/' + address), auth=self.auth)
        validate_response(
            self, r, required_keys=self.required_keys, status_code=200)


class RegisterUserTest(unittest.TestCase):
    def setUp(self):
        self.auth = (APP_ID, APP_SECRET)
        self.demo_auth = ('', '')
        self.required_keys = ['status']

    def tearDown(self):
        pass

    def test_user_registration(self):
        payload = {
            'recipient_address': 'Mx73vJcnF4Xq7AawfePRKzYCoGivw87BmY',
            'passname': random_username(),
            'passcard': {'name': {'formatted': 'John Doe'}}
        }
        r = make_post_request(self, build_url('/users'), payload,
                              auth=self.auth)
        validate_response(
            self, r, required_keys=self.required_keys, status_code=200)


def test_main():
    test_support.run_unittest(
        LookupUsersTest,
        UserbaseStatsTest,
        SearchUsersTest,
        LookupAddressTest,
        # RegisterUserTest,
        # BroadcastTransactionTest
    )


if __name__ == '__main__':
    test_main()
