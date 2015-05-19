import unittest
import requests
from test import test_support

APP_ID = '39abc40158e78c6ae96c2a350401c56f'
APP_SECRET = 'd909fe1396accded7f7a3a449140ea5b6761605a1683d4df499fa583b406e541'
BASE_URL = 'http://localhost:5000'
API_VERSION = '1'


def build_url(pathname):
    return BASE_URL + '/v' + API_VERSION + pathname


class LookupUsersTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def endpoint_test(self, username, auth=None):
        url = build_url('/users/' + username)
        if auth:
            r = requests.get(url, auth=auth)
        else:
            r = requests.get(url)
        self.assertTrue(isinstance(r.json(), dict))
        return r, r.json()

    def test_unprotected_endpoint(self):
        username = 'fredwilson'
        r, data = self.endpoint_test(username, auth=(APP_ID, APP_SECRET))
        self.assertTrue(r.status_code == 200)
        self.assertTrue(username in data)

    def test_protected_endpoint_without_auth(self):
        username = 'albertwenger'
        r, data = self.endpoint_test(username)
        self.assertTrue(r.status_code == 400)
        self.assertTrue(username not in data)

    def test_protected_endpoint_with_auth(self):
        username = 'albertwenger'
        r, data = self.endpoint_test(username, auth=(APP_ID, APP_SECRET))
        self.assertTrue(r.status_code == 200)
        self.assertTrue(username in data)


class SampleTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass


def test_main():
    test_support.run_unittest(
        LookupUsersTest
    )

if __name__ == '__main__':
    test_main()
