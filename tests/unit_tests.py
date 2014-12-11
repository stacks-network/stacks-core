import json, traceback, unittest, string
from test import test_support

from opennamelib import *
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
    'name': 'ryanshea',
    'salt': '83675d4f5c112b74e86af99b7ec83cec',
    'data': """{  }""",
    'recipient': '1DuckDmHTXVxSHC7UafaBiUZB81qYhKprF'
}

class NamePreorderTest(unittest.TestCase):
    def setUp(self):
        self.data = registration_example_1

    def test_name_preorder(self):
        resp = preorder_name(
            self.data['name'], SECRETS['private_keys'][0],
            salt=self.data['salt'], blockchain_client=blockchain_client,
            testspace=True)
        print resp
        self.assertTrue('success' in resp)

class NameRegistrationTest(unittest.TestCase):
    def setUp(self):
        self.data = registration_example_1

    def tearDown(self):
        pass

    def test_name_registration(self):
        resp = register_name(
            self.data['name'], self.data['salt'], SECRETS['private_keys'][0],
            blockchain_client=blockchain_client, testspace=True)
        print resp
        self.assertTrue('success' in resp)

class NameUpdateTest(unittest.TestCase):
    def setUp(self):
        self.data = registration_example_1

    def tearDown(self):
        pass

    def test_name_update(self):
        resp = update_name(
            self.data['name'], self.data['data'], SECRETS['private_keys'][0],
            blockchain_client=blockchain_client, testspace=True)
        print resp 
        self.assertTrue('success' in resp)

class NameTransferTest(unittest.TestCase):
    def setUp(self):
        self.data = registration_example_1

    def tearDown(self):
        pass

    def test_name_transfer(self):
        resp = transfer_name(
            self.data['name'], self.data['recipient'],
            SECRETS['private_keys'][0], blockchain_client=blockchain_client,
            testspace=True)
        print resp
        self.assertTrue('success' in resp)

class MerkleRootTest(unittest.TestCase):
    def setUp(self):
        self.hashes = [
            'f484b014c55a43b409a59de3177d49a88149b4473f9a7b81ea9e3535d4b7a301',
            '7b5636e9bc6ec910157e88702699bc7892675e8b489632c9166764341a4d4cfe',
            'f8b02b8bf25cb6008e38eb5453a22c502f37e76375a86a0f0cfaa3c301aa1209'
        ]
        self.merkle_root = '4f4c8c201e85a64a410cc7272c77f443d8b8df3289c67af9dab1e87d9e61985e'

    def tearDown(self):
        pass

    def test_merkle_tree(self):
        merkle_tree = MerkleTree(self.hashes)
        self.assertEqual(merkle_tree.root(), self.merkle_root)

    def test_calculate_merkle_root(self):
        merkle_root = calculate_merkle_root(self.hashes)
        self.assertEqual(merkle_root, self.merkle_root)

"""class NameOperationSequenceTest(unittest.TestCase):
    def setUp(self):
        blockchain_client = ChainComClient(
            api_key_id=SECRETS['chain_api_id'],
            api_key_secret=SECRETS['chain_api_secret'])
        self.private_keys = SECRETS['private_keys']
        self.data = registration_example_1

    def tearDown(self):
        pass

    def test_name_preorder(self):
        resp = preorder_name(self.name, self.private_keys[0],
            blockchain_client=blockchain_client, testspace=True)
        self.salt = resp['salt']
        self.assertTrue('success' in resp)

        resp = register_name(self.name, self.salt, self.private_keys[1],
            blockchain_client=blockchain_client, testspace=True)
        self.assertTrue('success' in resp)

        resp = update_name(self.name, self.data, self.private_keys[2],
            blockchain_client=blockchain_client, testspace=True)        
        self.assertTrue('success' in resp)

        resp = transfer_name(self.name, self.recipient, self.private_keys[3],
            blockchain_client=blockchain_client, testspace=True)
        self.assertTrue('success' in resp)"""

def test_main():
    test_support.run_unittest(
        MerkleRootTest,
        #NamePreorderTest,
        #NameRegistrationTest,
        NameUpdateTest,
        #NameTransferTest,
        #NameOperationSequenceTest
    )

if __name__ == '__main__':
    test_main()
