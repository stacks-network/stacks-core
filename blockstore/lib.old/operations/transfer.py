from pybitcoin import embed_data_in_blockchain, BlockchainInfoClient, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script
 
from pybitcoin.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes
from ..fees import calculate_basic_name_tx_fee


def build(name, testset=False):
    """
    Takes in a name to transfer.  Name must include the namespace ID, but not the scheme.
    
    Record format:
    
    0     2  3  4                      39
    |-----|--|--|----------------------|
    magic op len name.ns_id (up to 34 bytes)
    """
    
    if name.startswith(NAME_SCHEME):
       raise Exception("Invalid name %s: must not start with %s" % (name, NAME_SCHEME))
    
    # without the scheme, name must be 34 bytes 
    if len(name) > LENGTHS['blockchain_id_name'] - LENGTHS['blockchain_id_scheme']:
       raise Exception("Name '%s' is too long; expected %s bytes" % (name, LENGTHS['blockchain_id_name'] - LENGTHS['blockchain_id_scheme']))
    
    name_hex = hexlify(name)
    readable_script = 'NAME_TRANSFER %i %s' % (len(name_hex), name_hex)
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script


def make_outputs( data, inputs, new_name_owner_address, change_address, format='bin', fee=None, op_return_amount=DEFAULT_OP_RETURN_VALUE, name_owner_amount=DEFAULT_DUST_SIZE):
   
    """ Builds the outputs for a name transfer operation.
    """
    if fee is None:
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


def broadcast(name, destination_address, private_key, blockchain_client=BlockchainInfoClient(), testset=False):
   
    nulldata = build(name, testset=testset)
    # get inputs and from address
    private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
    # build custom outputs here
    outputs = make_outputs(nulldata, inputs, destination_address, from_address, format='hex')
    # serialize, sign, and broadcast the tx
    response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_client)
    # response = {'success': True }
    response.update({'data': nulldata})
    # return the response
    return response


def get_recipient_from_nameop_outputs(outputs):
    for output in outputs:
        output_script = output['scriptPubKey']
        output_type = output_script.get('type')
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')
        output_addresses = output_script.get('addresses')
        if output_asm[0:9] != 'OP_RETURN' and output_hex:
            return output_hex
    return None

def parse(bin_payload, outputs):
    """
    # NOTE: first three bytes were stripped
    """
    
    name_len = ord(bin_payload[0:1])
    name = unhexlify( bin_payload[1:1+name_len] )
    return {
        'opcode': 'NAME_TRANSFER',
        'name': name,
        'recipient': get_recipient_from_nameop_outputs( outputs )
    }
