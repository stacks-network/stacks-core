# -*- coding: utf-8 -*-
#-----------------------
#    Open Name System
#    ~~~~~
#
#    :copyright: (c) 2014 by opennamesystem.org
#    :license: MIT, see LICENSE for more details.
#-----------------------
# Previous copyright, from bitcoin-python:
# Copyright (c) 2010 Witchspace <witchspace81@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
Namecoin RPC service, data objects.
"""
from .util import DStruct


class ServerInfo(DStruct):
    """
    Information object returned by :func:`~namecoinrpc.connection.NamecoinConnection.getinfo`.

    - *errors* -- Number of errors.

    - *blocks* -- Number of blocks.

    - *paytxfee* -- Amount of transaction fee to pay.

    - *keypoololdest* -- Oldest key in keypool.

    - *genproclimit* -- Processor limit for generation.

    - *connections* -- Number of connections to other clients.

    - *difficulty* -- Current generating difficulty.

    - *testnet* -- True if connected to testnet, False if on real network.

    - *version* -- Namecoin client version.

    - *proxy* -- Proxy configured in client.

    - *hashespersec* -- Number of hashes per second (if generation enabled).

    - *balance* -- Total current server balance.

    - *generate* -- True if generation enabled, False if not.

    - *unlocked_until* -- Timestamp (seconds since epoch) after which the wallet
                          will be/was locked (if wallet encryption is enabled).

    """


class AccountInfo(DStruct):
    """
    Information object returned by :func:`~namecoinrpc.connection.NamecoinConnection.listreceivedbyaccount`.

    - *account* -- The account of the receiving address.

    - *amount* -- Total amount received by the address.

    - *confirmations* -- Number of confirmations of the most recent transaction included.

    """


class AddressInfo(DStruct):
    """
    Information object returned by :func:`~namecoinrpc.connection.NamecoinConnection.listreceivedbyaddress`.

    - *address* -- Receiving address.

    - *account* -- The account of the receiving address.

    - *amount* -- Total amount received by the address.

    - *confirmations* -- Number of confirmations of the most recent transaction included.

    """


class TransactionInfo(DStruct):
    """
    Information object returned by :func:`~namecoinrpc.connection.NamecoinConnection.listtransactions`.

    - *account* -- account name.

    - *address* -- the address namecoins were sent to, or received from.
    
    - *category* -- will be generate, send, receive, or move.

    - *amount* -- amount of transaction.

    - *fee* -- Fee (if any) paid (only for send transactions).

    - *confirmations* -- number of confirmations (only for generate/send/receive).

    - *txid* -- transaction ID (only for generate/send/receive).

    - *otheraccount* -- account funds were moved to or from (only for move).

    - *message* -- message associated with transaction (only for send).

    - *to* -- message-to associated with transaction (only for send).
    """


class AddressValidation(DStruct):
    """
    Information object returned by :func:`~namecoinrpc.connection.NamecoinConnection.validateaddress`.

    - *isvalid* -- Validatity of address (:const:`True` or :const:`False`).

    - *ismine* -- :const:`True` if the address is in the server's wallet.

    - *address* -- Namecoin address.

    """


class WorkItem(DStruct):
    """
    Information object returned by :func:`~namecoinrpc.connection.NamecoinConnection.getwork`.

    - *midstate* -- Precomputed hash state after hashing the first half of the data.

    - *data* -- Block data.

    - *hash1* -- Formatted hash buffer for second hash.

    - *target* -- Little endian hash target.

    """


class MiningInfo(DStruct):
    """
    Information object returned by :func:`~namecoinrpc.connection.NamecoinConnection.getmininginfo`.

    - *blocks* -- Number of blocks.

    - *currentblocksize* -- Size of current block.

    - *currentblocktx* -- Number of transactions in current block.

    - *difficulty* -- Current generating difficulty.

    - *errors* -- Number of errors.

    - *generate* -- True if generation enabled, False if not.

    - *genproclimit* -- Processor limit for generation.

    - *hashespersec* -- Number of hashes per second (if generation enabled).

    - *pooledtx* -- Number of pooled transactions.

    - *testnet* -- True if connected to testnet, False if on real network.

    """
