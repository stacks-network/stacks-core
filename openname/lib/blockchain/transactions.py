from ..parsing import parse_nameop
from .nulldata import get_nulldata, has_nulldata
import traceback


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
        if not ('vout' in tx and tx_output_index < len(tx['vout'])):
            continue

        # grab the previous tx output (the current input)
        prev_tx_output = tx['vout'][tx_output_index]

        # make sure the previous tx output is valid
        if not ('scriptPubKey' in prev_tx_output and 'value' in prev_tx_output):
            continue

        # extract the script pubkey
        script_pubkey = prev_tx_output['scriptPubKey']
        # build and append the sender to the list of senders
        amount_in = int(prev_tx_output['value']*10**8)
        sender = {
            "script_pubkey": script_pubkey.get('hex'),
            "amount": amount_in,
            "addresses": script_pubkey.get('addresses')
        }
        senders.append(sender)
        # increment the total amount going in to the transaction
        total_in += amount_in

    # return the senders and the total in
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
    # print tx['fee']

    return tx


def get_tx(bitcoind, tx_hash):
    # lookup the raw tx using the tx hash
    try:
        tx = bitcoind.getrawtransaction(tx_hash, 1)
    except:
        # traceback.print_exc()
        return None
    return tx


def get_nulldata_txs_in_block(bitcoind, block_number):
    nulldata_txs = []

    block_hash = bitcoind.getblockhash(block_number)
    block_data = bitcoind.getblock(block_hash)

    if 'tx' not in block_data:
        return nulldata_txs

    tx_hashes = block_data['tx']
    for tx_hash in tx_hashes:
        tx = get_tx(bitcoind, tx_hash)
        if tx and has_nulldata(tx):
            nulldata_tx = process_nulldata_tx(bitcoind, tx)
            if nulldata_tx:
                nulldata_txs.append(nulldata_tx)

    return nulldata_txs
