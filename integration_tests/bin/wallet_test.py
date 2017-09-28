#!/usr/bin/env python2

import blockstack_client
import os
import sys
import json

# normal post-0.14.2 wallet, no multisig
wallet_current_singlesig = {
    'owner_privkey': 'e47a196ccc9bff922b10c2c5664f11afc28b0c787bd7b8393e583a9599f25ca301',
    'payment_privkey': 'cd2442e2a1ac886493cbb84fcefafd88f80ecccfae441bfeb2462db4093e338901',
    'data_privkey': 'd0ae5b1643c7f744c1b9c4a5f5885dbdc781af1f56db313bbf18dbc8f943640601',
    'owner_addresses': ['1JuXPKDweFYsNiECCm5fF4t3ZpVn7vFtkn'],
    'payment_addresses': ['1A1zaHEhR4UoKABdiUSe4EqK36uvf9FW4C'],
    'data_pubkeys': ['02ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377'],
    'data_pubkey': '02ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377',
    'version': '0.14.5',
}

# normal post-0.14.2 wallet, with uncompressed keys
wallet_current_singlesig_uncompressed = {
    'owner_privkey': 'e47a196ccc9bff922b10c2c5664f11afc28b0c787bd7b8393e583a9599f25ca3',
    'payment_privkey': 'cd2442e2a1ac886493cbb84fcefafd88f80ecccfae441bfeb2462db4093e3389',
    'data_privkey': 'd0ae5b1643c7f744c1b9c4a5f5885dbdc781af1f56db313bbf18dbc8f9436406',
    'owner_addresses': ['1F3M9T5MVGZvuAKiB2uvqNpCghKCtyBsXr'],
    'payment_addresses': ['1JA2pGCofAs9qXTugm3BEqyZUvjQuzG5aL'],
    'data_pubkeys': ['04ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377f60c7db1565f8237de3b0735d1075e37b41f23e1a73270dfad8b748f933b5624'],
    'data_pubkey': '04ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377f60c7db1565f8237de3b0735d1075e37b41f23e1a73270dfad8b748f933b5624',
    'version': '0.14.5',
}

# post-0.14.2 wallet, with uncompressed private keys but compressed key addresses 
wallet_current_singlesig_compressed_addr = {
    'owner_privkey': 'e47a196ccc9bff922b10c2c5664f11afc28b0c787bd7b8393e583a9599f25ca3',
    'payment_privkey': 'cd2442e2a1ac886493cbb84fcefafd88f80ecccfae441bfeb2462db4093e3389',
    'data_privkey': 'd0ae5b1643c7f744c1b9c4a5f5885dbdc781af1f56db313bbf18dbc8f9436406',
    'owner_addresses': ['1JuXPKDweFYsNiECCm5fF4t3ZpVn7vFtkn'],
    'payment_addresses': ['1A1zaHEhR4UoKABdiUSe4EqK36uvf9FW4C'],
    'data_pubkeys': ['02ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377'],
    'data_pubkey': '02ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377',
    'version': '0.14.5',
}

# post-0.14.2 wallet, with compressed private keys but uncompressed key addresses 
wallet_current_singlesig_uncompressed_addr = {
    'owner_privkey': 'e47a196ccc9bff922b10c2c5664f11afc28b0c787bd7b8393e583a9599f25ca301',
    'payment_privkey': 'cd2442e2a1ac886493cbb84fcefafd88f80ecccfae441bfeb2462db4093e338901',
    'data_privkey': 'd0ae5b1643c7f744c1b9c4a5f5885dbdc781af1f56db313bbf18dbc8f943640601',
    'owner_addresses': ['1F3M9T5MVGZvuAKiB2uvqNpCghKCtyBsXr'],
    'payment_addresses': ['1JA2pGCofAs9qXTugm3BEqyZUvjQuzG5aL'],
    'data_pubkeys': ['04ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377f60c7db1565f8237de3b0735d1075e37b41f23e1a73270dfad8b748f933b5624'],
    'data_pubkey': '04ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377f60c7db1565f8237de3b0735d1075e37b41f23e1a73270dfad8b748f933b5624',
    'version': '0.14.5',
}

# normal post-0.14.2 multisig wallet
wallet_current_multisig = {
    'owner_privkey': {
        "address": "3NQCpz7TSxijX5pgaSAk45chJXy1VaZdJF", 
        "private_keys": [
            "7624bacf35c1cfde1ffc2b06221d624ccde42c65a96c1fd701a136a904c81a7c01", 
            "6ba1ad4d4619bd069b64a530a6682596d2170a5cda177f9bb3db07bd7fb784eb01", 
            "d12e02c2981889c6b4d3f8368cb800ba1c7c5c60ddc210af634bcbf493cd546101"
        ], 
        "redeem_script": "522102a9b240cd7f91f148e0e18be3fa0da8d1a86166dda1a53fb57b87c14cf6d6d33e21029511d96a272a088d8f227a1297da86f257b4bf89569caad83f840db739f015d921026142ee8b3860a708018b6203d5e984046a1dbbd860371e4405c99db8e448977053ae"
    },
    'owner_addresses': ['3NQCpz7TSxijX5pgaSAk45chJXy1VaZdJF'],
    'payment_privkey': {
        "address": "3N1EgSedDjwnxW3iH1bDAgKMeeb1YPsb3f", 
        "private_keys": [
            "2206e91a3f55e45aee39fa94a4d4c60aa8e00540c8adae7a7b1c1f8d09742a9a01", 
            "11de5f8470cf7d39d4bca9fb9585793ffb20d6b5f9aacc33f8f7c30781fddf6101", 
            "8fdb54dce2ea90a3760d15b0ec76b01bedd4b8ec3529745080df33884c4ff55801"
        ], 
        "redeem_script": "522102bed0562ed45edb946c7777dc8b01c67e9cd504c8e5f6b1acc0fa01a736e2b5b821029c32c182204a6d5a363de0acba942ba98417f244543eade03ee68bd5729ef098210252bb4a033d37bbc8e009fcf129fb6d96d895a1fd47eb89fbaf37f4d04f4b60b653ae"
    },
    'payment_addresses': ['3N1EgSedDjwnxW3iH1bDAgKMeeb1YPsb3f'],
    'data_privkey': 'd0ae5b1643c7f744c1b9c4a5f5885dbdc781af1f56db313bbf18dbc8f943640601',
    'data_pubkey': '02ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377',
    'data_pubkeys': ['02ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377'],
    'version': '0.14.5',
}

# normal post-0.14.2 multisig wallet, uncompressed keys and redeem script (shouldn't happen when we use virtualchain to generate it)
wallet_current_multisig_uncompressed = {
    'owner_privkey': {
        "address": "35x3gJ1wpfF2qDnyF8ouuy6wsnaZwgN3KD",
        "private_keys": [
            "7624bacf35c1cfde1ffc2b06221d624ccde42c65a96c1fd701a136a904c81a7c",
            "6ba1ad4d4619bd069b64a530a6682596d2170a5cda177f9bb3db07bd7fb784eb",
            "d12e02c2981889c6b4d3f8368cb800ba1c7c5c60ddc210af634bcbf493cd5461"
        ], 
        "redeem_script": '524104a9b240cd7f91f148e0e18be3fa0da8d1a86166dda1a53fb57b87c14cf6d6d33e1291c557927ae366fcd0518b49550f1fe890e205b84ebd2a10dfe621f69a5ee441049511d96a272a088d8f227a1297da86f257b4bf89569caad83f840db739f015d95903a6fbb3b7fbf0b184fb50e08e0118fff667c9820c6bf71664d442b7ca2ad841046142ee8b3860a708018b6203d5e984046a1dbbd860371e4405c99db8e4489770395778883e3c616a638802c4cf4e44398ceacf7ee783e7fcab16ad58314dadea53ae',
    },
    'owner_addresses': ['35x3gJ1wpfF2qDnyF8ouuy6wsnaZwgN3KD'],
    'payment_privkey': {
        "address": "334SNP6fPcPjBJftfWdo1hMi7B7dLxAG53",
        "private_keys": [
            "2206e91a3f55e45aee39fa94a4d4c60aa8e00540c8adae7a7b1c1f8d09742a9a", 
            "11de5f8470cf7d39d4bca9fb9585793ffb20d6b5f9aacc33f8f7c30781fddf61", 
            "8fdb54dce2ea90a3760d15b0ec76b01bedd4b8ec3529745080df33884c4ff558"
        ], 
        "redeem_script": "524104bed0562ed45edb946c7777dc8b01c67e9cd504c8e5f6b1acc0fa01a736e2b5b82c5d888b1d6164e8a22731f54c5720c7f0d364a6e4b799b6de243b38a3fa080041049c32c182204a6d5a363de0acba942ba98417f244543eade03ee68bd5729ef0986bf8de32e6dd85f03d853b0bc772da284b4b3e60d25b938bcab183f0f94403da410452bb4a033d37bbc8e009fcf129fb6d96d895a1fd47eb89fbaf37f4d04f4b60b613913d8831690d87f8aa4a785dd4e2928893a0587683517981bf91133743774653ae",
    },
    'payment_addresses': ['334SNP6fPcPjBJftfWdo1hMi7B7dLxAG53'],
    'data_privkey': 'd0ae5b1643c7f744c1b9c4a5f5885dbdc781af1f56db313bbf18dbc8f9436406',
    'data_pubkeys': ['04ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377f60c7db1565f8237de3b0735d1075e37b41f23e1a73270dfad8b748f933b5624'],
    'data_pubkey': '04ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377f60c7db1565f8237de3b0735d1075e37b41f23e1a73270dfad8b748f933b5624',
    'version': '0.14.5',
}

# normal post-0.14.2 multisig wallet, with compressed keys and redeemscript but uncompressed addresses
wallet_current_multisig_uncompressed_addr = {
    'owner_privkey': {
        "address": "35x3gJ1wpfF2qDnyF8ouuy6wsnaZwgN3KD",
        "private_keys": [
            "7624bacf35c1cfde1ffc2b06221d624ccde42c65a96c1fd701a136a904c81a7c01", 
            "6ba1ad4d4619bd069b64a530a6682596d2170a5cda177f9bb3db07bd7fb784eb01", 
            "d12e02c2981889c6b4d3f8368cb800ba1c7c5c60ddc210af634bcbf493cd546101"
        ], 
        "redeem_script": "522102a9b240cd7f91f148e0e18be3fa0da8d1a86166dda1a53fb57b87c14cf6d6d33e21029511d96a272a088d8f227a1297da86f257b4bf89569caad83f840db739f015d921026142ee8b3860a708018b6203d5e984046a1dbbd860371e4405c99db8e448977053ae"
    },
    'owner_addresses': ["35x3gJ1wpfF2qDnyF8ouuy6wsnaZwgN3KD"],
    'payment_privkey': {
        "address": "334SNP6fPcPjBJftfWdo1hMi7B7dLxAG53",
        "private_keys": [
            "2206e91a3f55e45aee39fa94a4d4c60aa8e00540c8adae7a7b1c1f8d09742a9a01", 
            "11de5f8470cf7d39d4bca9fb9585793ffb20d6b5f9aacc33f8f7c30781fddf6101", 
            "8fdb54dce2ea90a3760d15b0ec76b01bedd4b8ec3529745080df33884c4ff55801"
        ], 
        "redeem_script": "522102bed0562ed45edb946c7777dc8b01c67e9cd504c8e5f6b1acc0fa01a736e2b5b821029c32c182204a6d5a363de0acba942ba98417f244543eade03ee68bd5729ef098210252bb4a033d37bbc8e009fcf129fb6d96d895a1fd47eb89fbaf37f4d04f4b60b653ae"
    },
    'payment_addresses': ['334SNP6fPcPjBJftfWdo1hMi7B7dLxAG53'],
    'data_privkey': 'd0ae5b1643c7f744c1b9c4a5f5885dbdc781af1f56db313bbf18dbc8f9436406',
    'data_pubkeys': ['04ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377f60c7db1565f8237de3b0735d1075e37b41f23e1a73270dfad8b748f933b5624'],
    'data_pubkey': '04ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377f60c7db1565f8237de3b0735d1075e37b41f23e1a73270dfad8b748f933b5624',
    'version': '0.14.5',
}

# normal post-0.14.2 multisig wallet, with uncompressed keys and redeem script and compresed addresses
wallet_current_multisig_compressed_addr = {
    'owner_privkey': {
        "address": "3NQCpz7TSxijX5pgaSAk45chJXy1VaZdJF",
        "private_keys": [
            "7624bacf35c1cfde1ffc2b06221d624ccde42c65a96c1fd701a136a904c81a7c",
            "6ba1ad4d4619bd069b64a530a6682596d2170a5cda177f9bb3db07bd7fb784eb",
            "d12e02c2981889c6b4d3f8368cb800ba1c7c5c60ddc210af634bcbf493cd5461"
        ], 
        "redeem_script": '524104a9b240cd7f91f148e0e18be3fa0da8d1a86166dda1a53fb57b87c14cf6d6d33e1291c557927ae366fcd0518b49550f1fe890e205b84ebd2a10dfe621f69a5ee441049511d96a272a088d8f227a1297da86f257b4bf89569caad83f840db739f015d95903a6fbb3b7fbf0b184fb50e08e0118fff667c9820c6bf71664d442b7ca2ad841046142ee8b3860a708018b6203d5e984046a1dbbd860371e4405c99db8e4489770395778883e3c616a638802c4cf4e44398ceacf7ee783e7fcab16ad58314dadea53ae',
    },
    'owner_addresses': ['3NQCpz7TSxijX5pgaSAk45chJXy1VaZdJF'],
    'payment_privkey': {
        "address": "3N1EgSedDjwnxW3iH1bDAgKMeeb1YPsb3f",
        "private_keys": [
            "2206e91a3f55e45aee39fa94a4d4c60aa8e00540c8adae7a7b1c1f8d09742a9a", 
            "11de5f8470cf7d39d4bca9fb9585793ffb20d6b5f9aacc33f8f7c30781fddf61", 
            "8fdb54dce2ea90a3760d15b0ec76b01bedd4b8ec3529745080df33884c4ff558"
        ], 
        "redeem_script": "524104bed0562ed45edb946c7777dc8b01c67e9cd504c8e5f6b1acc0fa01a736e2b5b82c5d888b1d6164e8a22731f54c5720c7f0d364a6e4b799b6de243b38a3fa080041049c32c182204a6d5a363de0acba942ba98417f244543eade03ee68bd5729ef0986bf8de32e6dd85f03d853b0bc772da284b4b3e60d25b938bcab183f0f94403da410452bb4a033d37bbc8e009fcf129fb6d96d895a1fd47eb89fbaf37f4d04f4b60b613913d8831690d87f8aa4a785dd4e2928893a0587683517981bf91133743774653ae",
    },
    'payment_addresses': ['3N1EgSedDjwnxW3iH1bDAgKMeeb1YPsb3f'],
    'data_privkey': 'd0ae5b1643c7f744c1b9c4a5f5885dbdc781af1f56db313bbf18dbc8f943640601',
    'data_pubkey': '02ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377',
    'data_pubkeys': ['02ab79cffb6ddcb96977d84eb5292390c9a28b1112b43d20b5c28ff70d8a303377'],
    'version': '0.14.5',
}

enc_wallet_current_singlesig = blockstack_client.wallet.encrypt_wallet(wallet_current_singlesig, "0123456789abcdef")
enc_wallet_current_singlesig_uncompressed = blockstack_client.wallet.encrypt_wallet(wallet_current_singlesig_uncompressed, "0123456789abcdef")
enc_wallet_current_singlesig_compressed_addr = blockstack_client.wallet.encrypt_wallet(wallet_current_singlesig_compressed_addr, "0123456789abcdef")
enc_wallet_current_singlesig_uncompressed_addr = blockstack_client.wallet.encrypt_wallet(wallet_current_singlesig_uncompressed_addr, "0123456789abcdef")
enc_wallet_current_multisig = blockstack_client.wallet.encrypt_wallet(wallet_current_multisig, "0123456789abcdef")
enc_wallet_current_multisig_uncompressed = blockstack_client.wallet.encrypt_wallet(wallet_current_multisig_uncompressed, "0123456789abcdef")
enc_wallet_current_multisig_compressed_addr = blockstack_client.wallet.encrypt_wallet(wallet_current_multisig_compressed_addr, "0123456789abcdef")
enc_wallet_current_multisig_uncompressed_addr = blockstack_client.wallet.encrypt_wallet(wallet_current_multisig_uncompressed_addr, "0123456789abcdef")

def wallet_cmp(w1, w2):
    w1_nodatapubkey = {}
    w2_nodatapubkey = {}
    w1_nodatapubkey.update(w1)
    w2_nodatapubkey.update(w2)

    del w1_nodatapubkey['data_pubkey']
    del w1_nodatapubkey['data_pubkeys']
    del w2_nodatapubkey['data_pubkey']
    del w2_nodatapubkey['data_pubkeys']
    
    return w1_nodatapubkey == w2_nodatapubkey


w = blockstack_client.wallet.decrypt_wallet(enc_wallet_current_singlesig, "0123456789abcdef")
assert 'error' not in w, w
assert wallet_cmp(w['wallet'], wallet_current_singlesig), json.dumps(w['wallet'], indent=4, sort_keys=True)

w = blockstack_client.wallet.decrypt_wallet(enc_wallet_current_singlesig_uncompressed, "0123456789abcdef")
assert 'error' not in w, w
assert wallet_cmp(w['wallet'], wallet_current_singlesig_uncompressed), json.dumps(w['wallet'], indent=4, sort_keys=True)

w = blockstack_client.wallet.decrypt_wallet(enc_wallet_current_singlesig_compressed_addr, "0123456789abcdef")
assert 'error' not in w, w
assert wallet_cmp(w['wallet'], wallet_current_singlesig), json.dumps(w['wallet'], indent=4, sort_keys=True)

w = blockstack_client.wallet.decrypt_wallet(enc_wallet_current_singlesig_uncompressed_addr, "0123456789abcdef")
assert 'error' not in w, w
assert wallet_cmp(w['wallet'], wallet_current_singlesig_uncompressed), json.dumps(w['wallet'], indent=4, sort_keys=True)

w = blockstack_client.wallet.decrypt_wallet(enc_wallet_current_multisig, "0123456789abcdef")
assert 'error' not in w, w
assert wallet_cmp(w['wallet'], wallet_current_multisig), json.dumps(w['wallet'], indent=4, sort_keys=True)

w = blockstack_client.wallet.decrypt_wallet(enc_wallet_current_multisig_uncompressed, '0123456789abcdef')
assert 'error' not in w, w
assert wallet_cmp(w['wallet'], wallet_current_multisig_uncompressed), json.dumps(w['wallet'], indent=4, sort_keys=True)

w = blockstack_client.wallet.decrypt_wallet(enc_wallet_current_multisig_uncompressed_addr, '0123456789abcdef')
assert 'error' not in w, w
assert wallet_cmp(w['wallet'], wallet_current_multisig_uncompressed), json.dumps(w['wallet'], indent=4, sort_keys=True)

w = blockstack_client.wallet.decrypt_wallet(enc_wallet_current_multisig_compressed_addr, '0123456789abcdef')
assert 'error' not in w, w
assert wallet_cmp(w['wallet'], wallet_current_multisig), json.dumps(w['wallet'], indent=4, sort_keys=True)

