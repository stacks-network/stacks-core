import json, traceback, unittest, string
from test import test_support

from pyopenname import *
from coinkit import *

try:
    with open('data/secrets.json', 'r') as f:
        SECRETS = json.loads(f.read())
except:
    traceback.print_exc()

blockchain_client = ChainComClient(
    api_key_id=SECRETS['chain_api_id'],
    api_key_secret=SECRETS['chain_api_secret'])

registration_example_1 = {
    'name': 'ryan',
    'salt': '83675d4f5c112b74e86af99b7ec83cec',
    'data': """{ "name": { "formatted": "Ryan Shea" } }""",
    'recipient': '1DuckDmHTXVxSHC7UafaBiUZB81qYhKprF'
}

class NamePreorderTest(unittest.TestCase):
    def setUp(self):
        self.data = registration_example_1

    def test_name_preorder(self):
        resp = preorder_name(self.data['name'], SECRETS['private_keys'][0],
            salt=self.data['salt'], blockchain_client=blockchain_client,
            testspace=True)
        print resp
        self.assertTrue('success' in resp)

class NameClaimTest(unittest.TestCase):
    def setUp(self):
        self.data = registration_example_1

    def tearDown(self):
        pass

    def test_name_claim(self):
        resp = claim_name(self.data['name'], self.data['salt'], SECRETS['private_keys'][0],
            blockchain_client=blockchain_client, testspace=True)
        print resp
        self.assertTrue('success' in resp)

class NameUpdateTest(unittest.TestCase):
    def setUp(self):
        self.data = registration_example_1

    def tearDown(self):
        pass

    def test_name_update(self):
        resp = update_name(self.data['name'], self.data['data'], SECRETS['private_keys'][0],
            blockchain_client=blockchain_client, testspace=True)
        print resp 
        self.assertTrue('success' in resp)

class NameTransferTest(unittest.TestCase):
    def setUp(self):
        self.data = registration_example_1

    def tearDown(self):
        pass

    def test_name_transfer(self):
        resp = transfer_name(self.data['name'], self.data['recipient'], SECRETS['private_keys'][0],
            blockchain_client=blockchain_client, testspace=True)
        print resp
        self.assertTrue('success' in resp)

class NameOperationSequenceTest(unittest.TestCase):
    def setUp(self):
        blockchain_client = ChainComClient(
            api_key_id=SECRETS['chain_api_id'],
            api_key_secret=SECRETS['chain_api_secret'])
        self.private_keys = SECRETS['private_keys']
        self.name = 'bitcoin'
        self.data = """{}"""
        self.recipient = '13DuSdJGZzeyBpGpXH1qKmZb8KDtuvPtwU'

    def tearDown(self):
        pass

    def test_name_preorder(self):
        resp = preorder_name(self.name, self.private_keys[0],
            blockchain_client=blockchain_client, testspace=True)
        self.salt = resp['salt']
        self.assertTrue('success' in resp)

        resp = claim_name(self.name, self.salt, self.private_keys[0],
            blockchain_client=blockchain_client, testspace=True)
        self.assertTrue('success' in resp)

        resp = update_name(self.name, self.data, self.private_keys[2],
            blockchain_client=blockchain_client, testspace=True)        
        self.assertTrue('success' in resp)

        resp = transfer_name(self.name, self.recipient, self.private_keys[3],
            blockchain_client=blockchain_client, testspace=True)
        self.assertTrue('success' in resp)

def test_main():
    test_support.run_unittest(
        NamePreorderTest,
        #NameClaimTest,
        #NameUpdateTest,
        #NameTransferTest,
        #NameOperationSequenceTest
    )

if __name__ == '__main__':
    test_main()
