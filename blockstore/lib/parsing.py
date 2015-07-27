from binascii import hexlify, unhexlify
from utilitybelt import is_hex, hex_to_charset, charset_to_hex

from .config import *
from .b40 import bin_to_b40
from .operations import parse_preorder, parse_registration, parse_update, \
    parse_transfer, parse_putdata, parse_rmdata, parse_namespacedefine, parse_namespacebegin


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


def parse_blockstore_op_data(data):
    """
    Parse a string of binary data (nulldata from a blockchain transaction) into a blockstore operation.
    
    data format (once unhex'ed):
    
    0           2     3                                   40
    |-----------|-----|-----------------------------------|
    magic bytes op    payload
    
    For registered names, bytes 0-3 are 'i', 'd', ':', since 
    name registrations occur as id://name.ns_id verbatum.
    
    For all other operations, "magic bytes" and "op" are our own 
    special values.
    """
    
    if not is_hex(data):
        raise ValueError('Data must be hex')
    
    if not len(data) % 2 == 0:
        # raise ValueError('Data must have an even number of bytes')
        return None

    try:
        bin_data = unhexlify(data)
    except:
        raise Exception('Invalid data supplied: %s' % data)

    # not a registered name, but a full-on operation?
    if bin_data[0:3] != NAME_SCHEME[0:3]:
       
       magic_bytes, opcode, payload = bin_data[0:2], bin_data[2:3], bin_data[3:]

       if not magic_bytes == MAGIC_BYTES:
         # Magic bytes don't match - not an openname operation.
         return None

    else:
        # this is a name registration
        opcode = NAME_REGISTRATION
        payload = bin_data

    op = None 
    
    if opcode == NAME_PREORDER and len(payload) >= MIN_OP_LENGTHS['preorder']:
        print "Parse NAME_PREORDER: %s" % data
        op = parse_preorder(payload)
        
    elif (opcode == NAME_REGISTRATION and len(payload) >= MIN_OP_LENGTHS['registration']):
        print "Parse NAME_REGISTRATION: %s" % data
        op = parse_registration(payload)
        
    elif opcode == NAME_UPDATE and len(payload) >= MIN_OP_LENGTHS['update']:
        print "Parse NAME_UPDATE: %s" % data
        op = parse_update(payload)
        
    elif (opcode == NAME_TRANSFER and len(payload) >= MIN_OP_LENGTHS['transfer']):
        print "Parse NAME_TRANSFER: %s" % data
        op = parse_transfer(payload)
      
    elif opcode == NAMESPACE_DEFINE and len(payload) >= MIN_OP_LENGTHS['namespace_define']:
        print "Parse NAMESPACE_DEFINE: %s" % data
        op = parse_namespacedefine( payload )
         
    elif opcode == NAMESPACE_BEGIN and len(payload) >= MIN_OP_LENGTHS['namespace_begin']:
        print "Parse NAMESPACE_BEGIN: %s" % data
        op = parse_namespacebegin( payload )
        
    elif opcode == DATA_PUT and len(payload) >= MIN_OP_LENGTHS['data_put']:
        print "Parse DATA_PUT: %s" % data
        op = parse_putdata( payload )
   
    elif opcode == DATA_REMOVE and len(payload) >= MIN_OP_LENGTHS['data_remove']:
        print "Parse DATA_REMOVE: %s" % data
        op = parse_rmdata( payload )
    
    return op


def analyze_op_outputs(nameop, outputs):
    """
    Perform opcode-specific analysis on blockstore operations,
    e.g. inserting new data into the operation as a post-processing step.
    
    Name transfers: fill in 'recipient' with the hex string of the script_pubkey of the recipient principal.
    """
    
    if eval(nameop['opcode']) == NAME_TRANSFER:
        recipient = get_recipient_from_nameop_outputs(outputs)
        nameop.update({'recipient': recipient})
        
    return nameop


def parse_blockstore_op(data, outputs, senders=None, fee=None):
    """
    Parse a blockstore operation from a transaction's nulldata (data) and a list of outputs, as well as 
    optionally the list of transaction's senders and the total fee paid.
    
    Return a parsed operation, and will also optionally have:
    * "sender": the first (primary) sender's script_pubkey, if there are any senders
    * "fee": the total fee paid for this record.
    """
    
    op = parse_blockstore_op_data(data)
    if op:
        
        op = analyze_op_outputs(op, outputs)
        
        if senders and len(senders) > 0 and 'script_pubkey' in senders[0]:
            primary_sender = str(senders[0]['script_pubkey'])
            op['sender'] = primary_sender
            
        if fee:
            op['fee'] = fee
            
    return op

