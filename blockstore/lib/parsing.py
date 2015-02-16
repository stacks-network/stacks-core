from binascii import hexlify, unhexlify
from utilitybelt import is_hex, hex_to_charset, charset_to_hex

from .config import *
from .b40 import bin_to_b40
from .operations import parse_preorder, parse_registration, parse_update, \
    parse_transfer


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
    # if not len(data) <= OP_RETURN_MAX_SIZE*2:
    #    raise ValueError('Payload too large')
    if not len(data) % 2 == 0:
        # raise ValueError('Data must have an even number of bytes')
        return None

    try:
        bin_data = unhexlify(data)
    except:
        raise Exception('Invalid data supplied: %s' % data)

    magic_bytes, opcode, payload = bin_data[0:2], bin_data[2:3], bin_data[3:]

    if not magic_bytes == MAGIC_BYTES:
        # Magic bytes don't match - not an openname operation.
        return None

    if opcode == NAME_PREORDER and len(payload) >= MIN_OP_LENGTHS['preorder']:
        nameop = parse_preorder(payload)
    elif (opcode == NAME_REGISTRATION
            and len(payload) >= MIN_OP_LENGTHS['registration']):
        nameop = parse_registration(payload)
    elif opcode == NAME_UPDATE and len(payload) >= MIN_OP_LENGTHS['update']:
        nameop = parse_update(payload)
    elif (opcode == NAME_TRANSFER
          and len(payload) >= MIN_OP_LENGTHS['transfer']):
        nameop = parse_transfer(payload)
    else:
        nameop = None

    return nameop


def analyze_nameop_outputs(nameop, outputs):
    if eval(nameop['opcode']) == NAME_TRANSFER:
        recipient = get_recipient_from_nameop_outputs(outputs)
        nameop.update({'recipient': recipient})
    return nameop


def parse_nameop(data, outputs, senders=None, fee=None):
    nameop = parse_nameop_data(data)
    if nameop:
        nameop = analyze_nameop_outputs(nameop, outputs)
        if senders and len(senders) > 0 and 'script_pubkey' in senders[0]:
            primary_sender = str(senders[0]['script_pubkey'])
            nameop['sender'] = primary_sender
        if fee:
            nameop['fee'] = fee
    return nameop
