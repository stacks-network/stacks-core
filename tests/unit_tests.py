import unittest
import requests
from test import test_support

APP_ID = '39abc40158e78c6ae96c2a350401c56f'
APP_SECRET = 'd909fe1396accded7f7a3a449140ea5b6761605a1683d4df499fa583b406e541'
BASE_URL = 'http://localhost:5000'
API_VERSION = '1'


def build_url(pathname):
    return BASE_URL + '/v' + API_VERSION + pathname


def make_request(cls, url, auth=None):
    if auth:
        r = requests.get(url, auth=auth)
    else:
        r = requests.get(url)
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

    def test_unprotected_endpoint(self):
        usernames = ['fredwilson']
        r = make_request(self, self.build_url(usernames), auth=self.demo_auth)
        validate_response(self, r, required_keys=usernames, status_code=200)

    def test_protected_endpoint_without_auth(self):
        usernames = ['naval']
        r = make_request(self, self.build_url(usernames))
        validate_response(self, r, banned_keys=usernames, status_code=400)

    def test_protected_endpoint_with_auth(self):
        usernames = ['naval']
        r = make_request(self, self.build_url(usernames), auth=self.auth)
        validate_response(self, r, required_keys=usernames, status_code=200)

    def test_multiple_users(self):
        usernames = ['fredwilson', 'naval', 'albertwenger']
        r = make_request(self, self.build_url(usernames), auth=self.auth)
        validate_response(self, r, required_keys=usernames, status_code=200)


def test_main():
    test_support.run_unittest(
        LookupUsersTest
    )

if __name__ == '__main__':
    test_main()
