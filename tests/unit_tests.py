import json, traceback, unittest, string
from test import test_support

from pyopenname import *
from coinkit import *

try:
    with open('data/secrets.json', 'r') as f:
        SECRETS = json.loads(f.read())
except:
    traceback.print_exc()

class NameOperationTest(unittest.TestCase):
    def setUp(self):
        self.blockchain_client = ChainComClient(
            api_key_id=SECRETS['chain_api_id'],
            api_key_secret=SECRETS['chain_api_secret'])
        self.private_keys = SECRETS['private_keys']
        self.name = 'ryan'
        self.data = """{ "name": { "formatted": "Ryan Shea" } }"""
        self.recipient = '13DuSdJGZzeyBpGpXH1qKmZb8KDtuvPtwU'

    def tearDown(self):
        pass

    def test_name_preorder(self):
        resp = preorder_name(self.name, self.private_keys[0],
            blockchain_client=self.blockchain_client, testnet=True)
        self.salt = resp['salt']
        self.assertTrue('success' in resp)

    def test_name_claim(self):
        self.salt = gen_name_preorder_salt()
        resp = claim_name(self.name, self.salt, self.private_keys[1],
            blockchain_client=self.blockchain_client, testnet=True)
        self.assertTrue('success' in resp)

    def test_name_stamp(self):
        resp = stamp_name(self.name, self.data, self.private_keys[2],
            blockchain_client=self.blockchain_client, testnet=True)        
        self.assertTrue('success' in resp)

    def test_name_transfer(self):
        resp = transfer_name(self.name, self.recipient, self.private_keys[3],
            blockchain_client=self.blockchain_client, testnet=True)
        self.assertTrue('success' in resp)

class NameOperationSequenceTest(unittest.TestCase):
    def setUp(self):
        self.blockchain_client = ChainComClient(
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
            blockchain_client=self.blockchain_client, testnet=True)
        self.salt = resp['salt']
        self.assertTrue('success' in resp)

        resp = claim_name(self.name, self.salt, self.private_keys[1],
            blockchain_client=self.blockchain_client, testnet=True)
        self.assertTrue('success' in resp)

        resp = stamp_name(self.name, self.data, self.private_keys[2],
            blockchain_client=self.blockchain_client, testnet=True)        
        self.assertTrue('success' in resp)

        resp = transfer_name(self.name, self.recipient, self.private_keys[3],
            blockchain_client=self.blockchain_client, testnet=True)
        self.assertTrue('success' in resp)

def test_main():
    test_support.run_unittest(
        NameOperationTest,
        #NameOperationSequenceTest
    )

if __name__ == '__main__':
    test_main()