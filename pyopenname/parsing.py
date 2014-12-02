from binascii import hexlify, unhexlify
from utilitybelt import is_hex, hex_to_charset, charset_to_hex

from .configs import *
from .b40 import bin_to_b40

def parse_name_preorder(bin_payload):
    name_hash = bin_payload[0:LENGTHS['name_hash']]
    return {
        'opcode': 'NAME_PREORDER', 'hash': hexlify(name_hash)
    }

def parse_name_claim(bin_payload):
    name_len = ord(bin_payload[0:1])
    name = bin_payload[1:1+name_len]
    salt = bin_payload[1+name_len:1+name_len+LENGTHS['salt']]
    return {
        'opcode': 'NAME_CLAIM', 'name': bin_to_b40(name), 'salt': hexlify(salt)
    }

def parse_name_update(bin_payload):
    name_len = ord(bin_payload[0:1])
    name = bin_payload[1:1+name_len]
    update = bin_payload[1+name_len:1+name_len+LENGTHS['update_hash']]
    return {
        'opcode': 'NAME_UPDATE', 'name': bin_to_b40(name), 'update': hexlify(update)
    }

def parse_name_transfer(bin_payload):
    name_len = ord(bin_payload[0:1])
    name = bin_payload[1:1+name_len]
    return {
        'opcode': 'NAME_TRANSFER', 'name': bin_to_b40(name), 'recipient': None
    }

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

def parse_nameop_data(data):
    if not is_hex(data):
        raise ValueError('Data must be hex')
    if not len(data) <= OP_RETURN_MAX_SIZE*2:
        raise ValueError('Payload too large')

    bin_data = unhexlify(data)

    magic_bytes, opcode, payload = bin_data[0:2], bin_data[2:3], bin_data[3:]

    if magic_bytes == MAGIC_BYTES_MAINSPACE:
        blockchain = 'main'
    elif magic_bytes == MAGIC_BYTES_TESTSPACE:
        blockchain = 'test'
    else:
        return None # Magic bytes don't match - not an openname operation.

    if opcode == NAME_PREORDER and len(payload) >= LENGTHS['name_hash']:
        nameop = parse_name_preorder(payload)
    elif opcode == NAME_CLAIM and len(payload) >= LENGTHS['name_min']+LENGTHS['salt']:
        nameop = parse_name_claim(payload)
    elif opcode == NAME_UPDATE and len(payload) >= LENGTHS['name_min']+LENGTHS['update_hash']:
        nameop = parse_name_update(payload)
    elif opcode == NAME_TRANSFER:
        nameop = parse_name_transfer(payload)
    else:
        nameop = None

    return nameop

def analyze_nameop_outputs(nameop, outputs):
    if eval(nameop['opcode']) == NAME_TRANSFER:
        recipient = get_recipient_from_nameop_outputs(outputs)
        nameop.update({ 'recipient': recipient })
    return nameop

def parse_nameop(data, outputs):
    nameop = parse_nameop_data(data)
    if nameop:
        nameop = analyze_nameop_outputs(nameop, outputs)
    return nameop
