from collections import defaultdict

from ..parsing import parse_nameop

def get_nulldata(tx):
    if not ('vout' in tx):
        return None        
    outputs = tx['vout']
    # go through all the outputs
    for output in outputs:
        # make sure the output is valid
        if not ('scriptPubKey' in output):
            continue
        # grab the script pubkey
        script_pubkey = output['scriptPubKey']
        # get the script parts and script type
        script_parts = str(script_pubkey.get('asm')).split(' ')
        script_type = str(script_pubkey.get('type'))
        # if we're looking at a nulldata tx, get the nulldata
        if script_type == 'nulldata' and len(script_parts) == 2:
            return script_parts[1]
    return None

def has_nulldata(tx):
    return (get_nulldata(tx) is not None)

def get_senders_and_total_in(bitcoind, inputs):
    senders = []
    total_in = 0
    # analyze the inputs for the senders and the total amount in
    for input in inputs:
        # make sure the input is valid
        if not ('txid' in input and 'vout' in input):
            continue

        # get the tx data for the specified input
        tx_hash = input['txid']
        tx_output_index = input['vout']
        tx = bitcoind.getrawtransaction(tx_hash, 1)

        # make sure the tx is valid
        if not ('vout' in tx and tx_output_index in tx['vout']):
            continue
        
        # grab the previous tx output (the current input)
        prev_tx_output = tx['vout'][tx_output_index]

        # make sure the previous tx output is valid
        if not ('scriptPubKey' in prev_tx_output and 'value' in prev_tx_output):
            continue
        
        # extract the script pubkey
        script_pubkey = prev_tx_output['scriptPubKey']
        # build and append the sender to the list of senders
        sender = {
            "script_pubkey": script_pubkey.get('hex'),
            "amount": int(prev_tx_output['value']*10**8),
            "addresses": script_pubkey.get('addresses')
        }
        senders.append(sender)
        # increment the total amount going in to the transaction
        total_in += amount_in
    return senders, total_in

def get_total_out(bitcoind, outputs):
    total_out = 0
    # analyze the outputs for the total amount out
    for output in outputs:
        amount_out = int(output['value']*10**8)
        total_out += amount_out
    return total_out

def process_nulldata_tx(bitcoind, tx):
    if not ('vin' in tx and 'vout' in tx and 'txid' in tx):
        return None

    inputs, outputs, txid = tx['vin'], tx['vout'], tx['txid']
    senders, total_in = get_senders_and_total_in(bitcoind, inputs)
    total_out = get_total_out(bitcoind, outputs)
    nulldata = get_nulldata(tx)

    # extend the tx
    tx['nulldata'] = nulldata
    tx['senders'] = senders
    tx['fee'] = total_in - total_out

    return tx

def get_nulldata_txs_in_block(bitcoind, block_number):
    nulldata_txs = []

    block_hash = bitcoind.getblockhash(block_number)
    block_data = bitcoind.getblock(block_hash)

    if 'tx' not in block_data:
        return nulldata_txs

    tx_hashes = block_data['tx']
    for tx_hash in tx_hashes:
        tx = self.get_tx(tx_hash)
        #self.process_tx(tx)
        if has_nulldata(tx):
            nulldata_tx = process_nulldata_tx(tx)
            if nulldata_tx:
                nulldata_txs.append(nulldata_tx)

    return nulldata_txs

def nulldata_txs_to_nameops(txs):
    nameops = []

    for tx in txs:
        nameop = parse_nameop(
            tx['nulldata'], tx['vout'], tx['senders'], tx['fee'])
        nameops.append(nameop)

    return nameops

def get_nameops_in_block_range(bitcoind, first_block=0, last_block=None):
    nameops = []

    if not last_block:
        last_block = bitcoind.getblockcount()

    for block_number in range(first_block, last_block + 1):
        current_nulldata_txs = get_nulldata_txs_in_block(bitcoind, block_number)
        nameops = nulldata_txs_to_nameops(current_nulldata_txs)
        print (block_number, nameops)
        nameops.append((block_number, nameops))

    return nameops
