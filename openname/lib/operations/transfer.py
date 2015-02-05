from coinkit import embed_data_in_blockchain, BlockchainInfoClient, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script
from coinkit.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40
from ..config import *
from ..scripts import name_script_to_hex, add_magic_bytes
from ..fees import calculate_basic_name_tx_fee


def build(name, testset=False):
    """ Takes in a name to transfer.
    """
    hex_name = b40_to_hex(name)
    name_len = len(hex_name)/2

    readable_script = 'NAME_TRANSFER %i %s' % (name_len, hex_name)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)

    return packaged_script


def make_outputs(
        data, inputs, new_name_owner_address, change_address, format='bin',
        fee=None, op_return_amount=DEFAULT_OP_RETURN_VALUE,
        name_owner_amount=DEFAULT_DUST_SIZE):
    """ Builds the outputs for a name transfer operation.
    """
    if not fee:
        fee = calculate_basic_name_tx_fee()
    total_to_send = op_return_amount + name_owner_amount
    return [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": op_return_amount},
        # new name owner output
        {"script_hex": make_pay_to_address_script(new_name_owner_address),
         "value": name_owner_amount},
        # change output
        {"script_hex": make_pay_to_address_script(change_address),
         "value": calculate_change_amount(inputs, total_to_send, fee)}
    ]


def broadcast(name, destination_address, private_key,
              blockchain_client=BlockchainInfoClient(), testset=False):
    nulldata = build(name, testset=testset)
    # get inputs and from address
    private_key_obj, from_address, inputs = analyze_private_key(
        private_key, blockchain_client)
    # build custom outputs here
    outputs = make_outputs(
        nulldata, inputs, destination_address, from_address, format='hex')
    # serialize, sign, and broadcast the tx
    response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj,
                                            blockchain_client)
    # response = {'success': True }
    response.update({'data': nulldata})
    # return the response
    return response


def parse(bin_payload):
    name_len = ord(bin_payload[0:1])
    name = bin_payload[1:1+name_len]
    return {
        'opcode': 'NAME_TRANSFER',
        'name': bin_to_b40(name),
        'recipient': None
    }
