#!/usr/bin/env python3
"""
Usage:
This script is designed to be run from the command line. It takes one or more Bitcoin addresses
and outputs the extracted block commit data for these addresses.

Example command line usage:
python3 get_unconfirmed_block_commits.py [btcAddress1] [btcAddress2] ...
"""

import requests
import json
import sys

def read_api_endpoint(url):
    """
    Reads data from the specified API endpoint and returns the response.

    Args:
        url (str): The API endpoint URL.

    Returns:
        dict: JSON response from the API if successful, otherwise None.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for non-200 status codes
        return response.json()  # Assuming a JSON response
    except requests.exceptions.RequestException as e:
        return None

def is_block_commit(txn):
    """
    Determines whether a given transaction is a block commit.

    Args:
        txn (dict): The transaction data.

    Returns:
        bool: True if the transaction is a block commit, otherwise False.
    """
    try:
        vout = txn['vout']

        # Verify the number of recipients.
        assert(3 <= len(vout) <= 4)
        block_commit_txn = vout[0]
        to_stacker_txns = vout[1::2]

        # Verify block commit.
        # TODO: Add more verification steps if necessary.
        assert(block_commit_txn['scriptpubkey_type'] == "op_return")

        # Verify PoX Payouts.
        for to_stacker_txn in to_stacker_txns:
            # TODO: Add more verification steps if necessary.
            assert(to_stacker_txn['scriptpubkey_type'] != "op_return")

    except (Exception, AssertionError):
        return False
    return True

MEMPOOL_TXN_API = "https://mempool.space/api/address/{btcAddress}/txs/mempool"
def unconfirmed_block_commit_from_address(btcAddress):
    """
    Fetches the first unconfirmed block commit for a given Bitcoin address.

    Args:
        btcAddress (str): Bitcoin address.

    Returns:
        dict: The first transaction that is a block commit.
    """
    url = MEMPOOL_TXN_API.format(btcAddress=btcAddress)
    txns = read_api_endpoint(url)

    # Return only the first block commit transaction. This is good enough for now.
    for txn in txns:
        if is_block_commit(txn):
            return txn

def extracted_block_commit_data(txn):
    """
    Extracts data from a block commit transaction.

    Args:
        txn (dict): Block commit transaction.

    Returns:
        dict: Extracted data from the transaction, or None if extraction fails.
    """
    try:
        vout_start = 1
        vout_end = len(txn['vout']) - 1
        spent_utxo = txn['vin'][0]
        return {
            'txid': txn['txid'],
            'burn': sum(pox_payout['value'] for pox_payout in txn['vout'][vout_start:vout_end]),
            'address': spent_utxo['prevout']['scriptpubkey_address'],
            'pox_addrs': [txn['vout'][i]['scriptpubkey'] for i in range(vout_start,vout_end)],
            'input_txid': spent_utxo['txid'],
            'input_index': spent_utxo['vout'],
        }
    except Exception as e:
        return None

def block_commit_data(btcAddresses):
    """
    Fetches and extracts block commit data for a list of Bitcoin addresses.

    Args:
        btcAddresses (list): List of Bitcoin addresses.

    Returns:
        list: Extracted block commit data for each address.
    """
    return [extracted_block_commit_data(unconfirmed_block_commit_from_address(btcAddress)) \
            for btcAddress in btcAddresses]

def main():
    """
    Main function to run the script. Takes command line arguments as Bitcoin addresses.
    """
    btc_addresses = sys.argv[1:]
    if not btc_addresses:
        print("No Bitcoin addresses provided. Please provide at least one address.")
        return

    # Return the data by printing it to stdout.
    data = block_commit_data(btc_addresses)
    print(json.dumps([datum for datum in data if datum is not None], indent=1))

if __name__ == "__main__":
    main()
