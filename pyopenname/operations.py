from coinkit import BitcoindClient, ChainComClient, BlockchainInfoClient, \
    make_pay_to_address_script, make_op_return_script, \
    embed_data_in_blockchain, analyze_private_key, \
    hex_hash160, serialize_sign_and_broadcast
from coinkit.transactions.outputs import calculate_change_amount

from .scripts import build_preorder_name_script, build_claim_name_script, \
    build_update_name_script, build_transfer_name_script
from .b40 import is_b40
from .configs import *

def calculate_name_tx_fee():
    return DEFAULT_OP_RETURN_FEE

def preorder_name(name, private_key, salt=None,
                  blockchain_client=BlockchainInfoClient(), testspace=False):
    nulldata, salt = build_preorder_name_script(name, testspace=testspace,
        salt=salt)
    response = embed_data_in_blockchain(
        nulldata, private_key, blockchain_client, format='hex')
    #response = {'success': True }
    response.update({ 'data': nulldata, 'salt': salt })
    return response

def claim_name(name, salt, private_key,
               blockchain_client=BlockchainInfoClient(), testspace=False):
    nulldata = build_claim_name_script(name, salt, testspace=testspace)
    #response = {'success': True }
    response = embed_data_in_blockchain(
        nulldata, private_key, blockchain_client, format='hex')
    response.update({ 'data': nulldata })
    return response

def update_name(name, data, private_key,
               blockchain_client=BlockchainInfoClient(), testspace=False):
    nulldata = build_update_name_script(
        name, data_hash=hex_hash160(data), testspace=testspace)
    response = embed_data_in_blockchain(
        nulldata, private_key, blockchain_client, format='hex')
    #response = {'success': True }
    response.update({ 'data': nulldata })
    return response

def transfer_name(name, destination_address, private_key,
                  blockchain_client=BlockchainInfoClient(), testspace=False):
    nulldata = build_transfer_name_script(name, testspace=testspace)
    # get inputs and from address
    private_key_obj, from_address, inputs = analyze_private_key(
        private_key, blockchain_client)
    # build custom outputs here
    outputs = make_transfer_name_outputs(nulldata, inputs, destination_address,
                                         from_address, format='hex')
    # serialize, sign, and broadcast the tx
    response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj,
                                            blockchain_client)
    #response = {'success': True }
    response.update({ 'data': nulldata })
    # return the response
    return response

def make_transfer_name_outputs(
            data, inputs, new_name_owner_address,
            change_address, format='bin', fee=None,
            op_return_amount=DEFAULT_OP_RETURN_VALUE,
            name_owner_amount=DEFAULT_DUST_SIZE):
    """ Builds the outputs for a name transfer operation.
    """
    if not fee:
        fee = calculate_name_tx_fee()
    total_to_send = op_return_amount + name_owner_amount
    return [
        # main output
        { "script_hex": make_op_return_script(data, format=format),
          "value": op_return_amount },
        # new name owner output
        { "script_hex": make_pay_to_address_script(new_name_owner_address),
          "value": name_owner_amount },
        # change output
        { "script_hex": make_pay_to_address_script(change_address),
          "value": calculate_change_amount(inputs, total_to_send, fee) }
    ]
