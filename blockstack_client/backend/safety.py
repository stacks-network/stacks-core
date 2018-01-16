# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import os, json
import threading
import functools
import virtualchain

from ..constants import (
    TX_MIN_CONFIRMATIONS,
    CONFIG_PATH,
    APPROX_PREORDER_TX_LEN,
    APPROX_REGISTER_TX_LEN,
    APPROX_UPDATE_TX_LEN,
    APPROX_TRANSFER_TX_LEN,
    APPROX_REVOKE_TX_LEN,
    APPROX_RENEWAL_TX_LEN,
    BLOCKSTACK_DEBUG,
    BLOCKSTACK_TEST,
    APPROX_NAMESPACE_PREORDER_TX_LEN,
    APPROX_NAMESPACE_REVEAL_TX_LEN,
    APPROX_NAMESPACE_READY_TX_LEN,
    NAMESPACE_VERSION_PAY_TO_CREATOR,
    NAMESPACE_VERSION_PAY_TO_BURN
)

from ..proxy import (
    get_default_proxy,
    is_name_registered,
    get_names_owned_by_address,
    get_name_cost,
    is_namespace_revealed,
    is_namespace_ready,
    json_is_error,
    get_name_blockchain_record,
    get_namespace_cost,
    get_namespace_blockchain_record,
    get_num_names_in_namespace,
    getinfo,
    is_name_owner
)

from ..config import get_utxo_provider_client
from ..b40 import is_b40
from ..logger import get_logger
from ..utils import ScatterGather, ScatterGatherThread

from .blockchain import (
    get_balance, is_address_usable, get_utxos,
    can_receive_name 
)

from virtualchain.lib.ecdsalib import ecdsa_private_key

from ..scripts import UTXOException, is_name_valid, is_namespace_valid

log = get_logger('safety')

def check_valid_name(fqu):
    """
    Verify that a name is valid.
    Return None on success
    Return an error string on error
    """

    rc = is_name_valid(fqu)
    if rc:
        return None

    # get a coherent reason why
    if '.' not in fqu:
        msg = (
            'The name specified is invalid. '
            'Names must end with a period followed by a valid TLD.'
        )

        return msg

    name = fqu.split('.')[0]

    if not name:
        msg = (
            'The name specified is invalid. '
            'Names must be at least one character long, not including the TLD.'
        )

        return msg

    if not is_b40(name):
        msg = (
            'The name specified is invalid. '
            'Names may only contain lowercase alphanumeric characters '
            'and underscores.'
        )

        return msg

    if len(fqu) > 37 or len(fqu) < 3:
        msg = (
            'The name specified is invalid.  '
            'Fully-qualified names must be between 3 and 37 characters long.'
        )

        return msg

    return 'The name is invalid'


def check_valid_namespace(nsid):
    """
    Verify that a namespace ID is valid.
    Return None on success
    Return an error string on error
    """

    rc = is_namespace_valid(nsid)
    if rc:
        return None

    # get a coherent reason why
    if '.' in nsid or '+' in nsid:
        msg = (
            'The namespace specified is invalid.  '
            'Namespace IDs cannot have "." or "+" in them.'
        )

        return msg

    if not is_b40(nsid):
        msg = (
            'The namespace specified is invalid.  '
            'Namespace IDs may only contain alphanumeric characters and underscores.'
        )

        return msg

    return 'The namespace ID is invalid'



def operation_sanity_checks(fqu_or_ns, operations, scatter_gather, payment_privkey_info, owner_privkey_info, tx_fee_per_byte,
                            required_checks=[], min_confirmations=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH,
                            transfer_address=None, owner_address=None, zonefile_hash=None, burn_address=None, proxy=None):
    """
    Do a sanity check on carrying out a sequence of operations on a given name.
    Prime the given scatter/gather context with the set of necessary callbacks.

    Any update, transfer, renew, or revoke operation
    should pass these tests:
    * the payment address must have enough BTC for the transaction and dust fees
    * the owner address can't have any pending transactions
    * the payment address can't have any pending transactions

    If transferring:
    * the transfer address must be suitable for receiving the name

    If preordering or renewing:
    * the payment address must have enough BTC for the name cost

    If preordering:
    * the name must not be registered
    
    If not preordering:
    * name must be registered
    * name must be owned by the owner address

    If renewing:
    * can only set the value hash if we're in epoch 3+
    * can only change owner if we're in epoch 3+

    Return {'status': True} on success
    Return {'error': ...} on error
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    if owner_address is None:
        assert owner_privkey_info
        owner_address = virtualchain.get_privkey_address(owner_privkey_info)

    payment_address = virtualchain.get_privkey_address(payment_privkey_info)
    if transfer_address:
        transfer_address = str(transfer_address)
    
    sg = scatter_gather

    def _is_name_available():
        """
        is name available? (scatter/gather worker)
        """
        if is_name_registered(fqu_or_ns, proxy=proxy):
            return {'error': '{} is already registered.'.format(fqu_or_ns)}
        else:
            return {'status': True}

    def _is_name_registered():
        """
        is name taken already? (scatter/gather worker)
        """
        if not is_name_registered(fqu_or_ns, proxy=proxy):
            return {'error': '{} is not registered.'.format(fqu_or_ns)}
        else:
            return {'status': True}

    def _can_receive_name(addr):
        """
        can owner address receive name? (scatter/gather worker)
        """
        if not can_receive_name(addr, proxy=proxy):
            msg = 'Address {} owns too many names already.'.format(addr)
            return {'error': msg}
        else:
            return {'status': True}

    def _is_address_usable(addr):
        """
        does the given address have unconfirmed transactions? (scatter/gather worker)
        """
        utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_confirmations)
        if not is_address_usable(addr, utxo_client=utxo_client, config_path=config_path):
            msg = (
                'Address {} has insufficiently confirmed transactions. '
                'Wait and try later.'
            )
            msg = msg.format(addr)
            return {'error': msg}

        else:
            return {'status': True}

    def _is_name_owner(name, addr):
        """
        Is the given address the name owner?
        """
        res = is_name_owner(name, addr, proxy=proxy)
        if not res:
            return {'error': 'Address {} does not own {}'.format(addr, name)}

        return {'status': True}

    def _is_namespace_available(ns):
        """
        Is the given namespace available for preorder/reveal?
        """
        if not is_namespace_revealed(ns, proxy=proxy):
            return {'status': True}
        else:
            return {'error': 'Namespace is already revealed'}

    def _is_namespace_still_revealed(fqu_or_ns):
        """
        Is the given namespace ready?
        Takes a fully-qualified name or a namespace ID
        """
        ns = fqu_or_ns
        if '.' in fqu_or_ns:
            ns = fqu_or_ns.split('.')[1]

        if not is_namespace_revealed(ns, proxy=proxy):
            return {'error': 'Namespace is not revealed'}

        if is_namespace_ready(ns, proxy=proxy):
            return {'error': 'Namespace is already launched'}

        return {'status': True}

    def _is_namespace_revealer(ns, reveal_addr):
        """
        Is the given reveal address the revealer for this namespace?
        The namespace must already exist
        """
        reveal_addr = virtualchain.address_reencode(reveal_addr)
        if not virtualchain.is_singlesig_address(reveal_addr):
            return {'error': 'Invalid address; only p2pkh addresses are supported for namespace reveal'}

        res = get_namespace_blockchain_record(ns, proxy=proxy)
        if 'error' in res:
            return {'error': res['error']}

        if res['recipient_address'] != reveal_addr:
            return {'error': 'Wrong namespace reveal address'}

        return {'status': True}

    def _is_namespace_reveal_address_valid(reveal_address):
        """
        Is the given address suitable for issuing a namespace reveal?
        * must be a p2pkh address
        * must have no outstanding UTXOs
        """
        utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_confirmations)
        reveal_address = virtualchain.address_reencode(reveal_address)
        if not virtualchain.is_singlesig_address(reveal_address):
            return {'error': 'Invalid address; only p2pkh addresses are supported for namespace reveal'}
        
        return {'status': True}

    def _register_can_change_zonefile_hash(zonefile_hash):
        """
        If we're registering, can we set the value hash?
        """
        import blockstack
        if zonefile_hash is not None:
            indexer_info = getinfo()
            if 'error' in indexer_info:
                return {'error': 'Failed to contact indexer'}
            
            # +1, so we consider the next block to be formed.
            epoch_features = blockstack.get_epoch_features(indexer_info['last_block_seen']+1)
            if blockstack.EPOCH_FEATURE_OP_REGISTER_UPDATE not in epoch_features:
                # not active yet
                return {'error': 'NAME_REGISTRATION cannot set value hashes in this epoch (block {})'.format(indexer_info['last_block_seen'])}

            log.debug("Epoch feature '{}' is active!".format(blockstack.EPOCH_FEATURE_OP_REGISTER_UPDATE))

        return {'status': True}

    def _renewal_can_change_zonefile_hash(zonefile_hash):
        """
        If we're renewing, can we set the value hash?
        """
        import blockstack
        if zonefile_hash is not None:
            indexer_info = getinfo()
            if 'error' in indexer_info:
                return {'error': 'Failed to contact indexer'}

            # +1, so we consider the next block to be formed
            epoch_features = blockstack.get_epoch_features(indexer_info['last_block_seen']+1)
            if blockstack.EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
                # not active yet
                return {'error': 'NAME_RENEWAL cannot set value hashes in this epoch (block {})'.format(indexer_info['last_block_seen'])}

            log.debug("Epoch feature '{}' is active!".format(blockstack.EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE))

        return {'status': True}

    def _renewal_can_change_owner_address(transfer_address):
        """
        If we're renewing, can we set the transfer address?
        """
        import blockstack
        if transfer_address is not None and transfer_address != owner_address:
            indexer_info = getinfo()
            if 'error' in indexer_info:
                return {'error': 'Failed to contact indexer'}

            # +1, so we consider the next block to be formed
            epoch_features = blockstack.get_epoch_features(indexer_info['last_block_seen']+1)
            if blockstack.EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
                # not active yet
                return {'error': 'NAME_RENEWAL cannot change the owner in this epoch'}
            
            log.debug("Epoch feature '{}' is active!".format(blockstack.EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE))

        return {'status': True}

    def _is_burn_address_correct(fqu, burn_addr):
        """
        If we're preordering or registering, is the burn address valid?
        """
        import blockstack
        if burn_addr is not None:
            indexer_info = getinfo()
            if 'error' in indexer_info:
                return {'error': 'Failed to contact indexer'}

            # +1, so we consider the next block to be formed 
            block_height = indexer_info['last_block_seen'] + 1
            epoch_features = blockstack.get_epoch_features(block_height)
            if blockstack.EPOCH_FEATURE_NAMESPACE_BURN_TO_CREATOR not in epoch_features and virtualchain.address_reencode(burn_addr) != virtualchain.address_reencode(blockstack.BLOCKSTACK_BURN_ADDRESS):
                # not active yet 
                return {'error': 'cannot burn to namespace burn address (not allowed in this epoch)'}

            # what's the namespace burn address?
            nsid = blockstack.get_namespace_from_name(fqu)
            ns_info = get_namespace_blockchain_record(nsid)
            if 'error' in ns_info:
                return {'error': 'Failed to get namespace info for {}'.format(nsid)}

            ns_burn_address = None
            if (ns_info['version'] & NAMESPACE_VERSION_PAY_TO_BURN) != 0:
                # version-1 namespace: pay to null burn address
                ns_burn_address = blockstack.BLOCKSTACK_BURN_ADDRESS

            elif (ns_info['version'] & NAMESPACE_VERSION_PAY_TO_CREATOR) != 0:
                # version-2 namespace: pay to namespace creator if it's still in it's fee capture period
                receive_fees_period = blockstack.get_epoch_namespace_receive_fees_period(block_height, nsid)
                if ns_info['reveal_block'] + receive_fees_period >= block_height:
                    # use the namespace burn address
                    ns_burn_address = str(ns_info['address'])
                else:
                    # use the null burn address
                    ns_burn_address = blockstack.BLOCKSTACK_BURN_ADDRESS
            
            log.debug("Burn address for {} is {}".format(nsid, ns_burn_address))
            if virtualchain.address_reencode(str(burn_address)) != virtualchain.address_reencode(ns_burn_address):
                return {'error': 'wrong burn address: expected {}, got {}'.format(
                    virtualchain.address_reencode(ns_burn_address),
                    virtualchain.address_reencode(str(burn_address))
                )}

        return {'status': True}

    def _is_name_outside_grace_period(fqu):
        """
        Is the name outside the grace period?
        """
        import blockstack

        indexer_info = getinfo()
        if 'error' in indexer_info:
            return {'error': 'Failed to contact indexer'}

        # +1, so we consider the next block to be formed 
        block_number = indexer_info['last_block_seen']+1
        nsid = blockstack.get_namespace_from_name(fqu)

        name_rec = get_name_blockchain_record(fqu)
        if 'error' in name_rec:
            log.error("Failed to get name record for {}".format(fqu))
            return {'error': 'Failed to get name blockchain record for {}'.format(fqu)}
            
        namespace_rec = get_namespace_blockchain_record(nsid)
        if 'error' in namespace_rec:
            log.error('Failed to get namespace record for {}'.format(nsid))
            return {'error': 'Failed to get namespace record for {}'.format(nsid)}

        grace_info = blockstack.BlockstackDB.get_name_deadlines(name_rec, namespace_rec, block_number)
        if (block_number >= grace_info['expire_block'] and block_number < grace_info['renewal_deadline']):
            return {'error': 'Name {} is in the renewal grace period.  Only renewals are possible.'.format(fqu)}
           
        log.debug("Block number is {}, but grace period is between {} and {}".format(block_number, grace_info['expire_block'], grace_info['renewal_deadline']))
        return {'status': True}

    def _is_name_import_key(fqu_or_ns, import_privkey):
        """
        Is the given private key a valid derived key for importing a name
        into this namespace?
        * must be a single private key (for p2pkh)
        * must be derived from the reveal private key
        * if this is the first name imported, then the key must be equal to the reveal key
        """
        import blockstack

        nsid = fqu_or_ns
        if '.' in fqu_or_ns:
            nsid = blockstack.get_namespace_from_name(fqu_or_ns)

        if not virtualchain.is_singlesig(import_privkey):
            if BLOCKSTACK_TEST:
                log.debug("Not a single private key: {}".format(import_privkey))

            return {'error': 'Not a single private key'}

        built_keychain = False
        keychain_dir = os.path.join( os.path.dirname(config_path), 'import_keychains' )
        if not os.path.exists(keychain_dir):
            os.makedirs(keychain_dir)
            built_keychain = True

        keychain_path = blockstack.BlockstackDB.get_import_keychain_path(keychain_dir, nsid)
        if not os.path.exists(keychain_path):
            built_keychain = True

        def _cleanup():
            if built_keychain: 
                try:
                    os.unlink(keychain_path)
                except:
                    pass

            return

        child_addrs = blockstack.BlockstackDB.build_import_keychain( nsid, ecdsa_private_key(import_privkey).public_key().to_hex(), keychain_dir=keychain_dir )
        import_addr = virtualchain.get_privkey_address(import_privkey)

        if import_addr not in child_addrs:
            _cleanup()
            return {'error': 'Invalid import key'}

        # is this the first such name?
        res = get_num_names_in_namespace(nsid, proxy=proxy)
        if json_is_error(res):
            _cleanup()
            return {'error': res['error']}

        assert type(res) in [int, long]
        if res == 0:
            # this must be the same as the revealer key
            res = get_namespace_blockchain_record(nsid, proxy=proxy)
            if 'error' in res:
                _cleanup()
                return {'error': res['error']}

            if res['recipient_address'] != import_addr:
                _cleanup()
                return {'error': 'The first imported name must have the namespace reveal address as its owner'}

        # is this address usable?
        res = _is_address_usable(import_addr)
        if 'error' in res:
            _cleanup()
            return res

        return {'status': True}
        
    
    check_names = {
        'is_owner_address_usable': lambda: _is_address_usable(owner_address),
        'is_payment_address_usable': lambda: _is_address_usable(payment_address),
        'is_name_available': _is_name_available,
        'owner_can_receive': lambda: _can_receive_name(owner_address),
        'is_name_registered': _is_name_registered,
        'is_name_owner': lambda: _is_name_owner(fqu_or_ns, owner_address),
        'recipient_can_receive': lambda: _can_receive_name(transfer_address),
        'is_namespace_available': lambda: _is_namespace_available(fqu_or_ns),
        'is_namespace_still_revealed': lambda: _is_namespace_still_revealed(fqu_or_ns),
        'is_namespace_revealer': lambda: _is_namespace_revealer(fqu_or_ns, owner_address),
        'is_namespace_reveal_address_valid': lambda: _is_namespace_reveal_address_valid(owner_address),
        'is_name_import_key': lambda: _is_name_import_key(fqu_or_ns, payment_privkey_info),
        'register_can_change_zonefile_hash': lambda: _register_can_change_zonefile_hash(zonefile_hash),
        'renewal_can_change_zonefile_hash': lambda: _renewal_can_change_zonefile_hash(zonefile_hash),
        'renewal_can_change_owner_address': lambda: _renewal_can_change_owner_address(transfer_address),
        'is_burn_address_correct': lambda: _is_burn_address_correct(fqu_or_ns, burn_address),
        'is_name_outside_grace_period': lambda: _is_name_outside_grace_period(fqu_or_ns),
    }
    
    # common to all operations
    required = ['is_payment_address_usable']
    for req in required:
        if req not in required_checks:
            required_checks.append(req)

    # sanity check
    for req in required_checks:
        assert req in check_names.keys(), "Invalid check '{}'".format(req)

    # queue commands
    for req in required_checks:
        sg.add_task( req, check_names[req] )

    # add tasks for fees
    res = get_operation_fees(fqu_or_ns, operations, sg, payment_privkey_info, owner_privkey_info, tx_fee_per_byte,
                             payment_address=payment_address, owner_address=owner_address, transfer_address=transfer_address,
                             zonefile_hash=zonefile_hash, min_payment_confs=min_confirmations, config_path=config_path, proxy=proxy )

    if 'error' in res:
        log.error("Failed to get operation fees: {}".format(res['error']))
        return {'error': 'Failed to calculate transaction fees: {}'.format(res['error'])}

    log.debug("Queued tasks for {} on {}: {}".format(', '.join(operations), fqu_or_ns, ', '.join(sorted(sg.tasks.keys()))))

    # scatter/gather primed!
    return {'status': True}


def interpret_operation_sanity_checks( operations, scatter_gather ):
    """
    Interpret the set of scatter/gather task results.
    """

    reply = {}
    sg = scatter_gather

    # scan for errors
    errors = []
    all_results = sg.get_results()
    for res_key in all_results.keys():
        res = all_results[res_key]
        if 'error' in res:
            log.error("Task '{}' failed: {}".format(res_key, all_results[res_key]['error']))
            errors.append(all_results[res_key]['error'])
        
        else:
            reply[res_key] = all_results[res_key]['status']

    if 'get_balance' in reply:
        fees_reply = interpret_operation_fees( operations, sg, balance=reply['get_balance'] )
        if 'error' in fees_reply:
            errors.append(fees_reply['error'])
            del fees_reply['error']

        reply.update(fees_reply)

    if len(errors) > 0:
        reply['error'] = 'Operation sanity checks failed:\n\n{}'.format( '\n'.join(['  * ' + err for err in errors] ))

    return reply


def make_fake_input(addr, value=21 * 10**8):
    """
    Make a fake transaction input, based on the kind of input the given private key information
    is expected to create.
    """
    fake_input = {
        "transaction_hash": '00' * 32,
        'outpoint': {
            'index': 0,
            'hash': '00' * 32,
        },
        "value": value,
        "out_script": virtualchain.make_payment_script(addr),
        "confirmations": 256,
    }

    return fake_input


def estimate_transaction_inputs(operations, inputs, owner_address=None, payment_address=None):
    """
    Estimate the inputs that will be consumed by each
    operation's transaction.  These inputs do *not* correspond to the inputs
    that will actually be used, but are represenatitive of the *quantity*
    of inputs consumed by an operation and the *type* consumed.  It does *not*
    reflect the *value* consumed by the inputs.

    The first operation consumes all inputs, and emits one output
    that will be consumed by other inputs.

    @owner_address or @payment_address must be given (but not both)

    Returns {'status': True, 'inputs': [ [utxos], [utxos], ... ]}
    """

    op_inputs = []
    
    def _consolidate(inps):
        ret = inps[0]
        ret['value'] += sum([inp['value'] for inp in inps])
        return ret

    # one_input: what if all inputs were consolidated to a single input of the same value
    one_input = _consolidate(inputs)

    for i in xrange(0, len(operations)):
        if i == 0:
            # the first operation will consume everything, and emit a single output
            # to be consumed by the next operation 
            op_inputs.append(inputs[:])
            
        else:
            # operations consume one input
            op_inputs.append([one_input])
        
    return {'status': True, 'inputs': op_inputs} 


def get_operation_fees(name_or_ns, operations, scatter_gather, payment_privkey_info, owner_privkey_info, tx_fee_per_byte,
                       proxy=None, config_path=CONFIG_PATH, payment_address=None, zonefile_hash=None,
                       min_payment_confs=TX_MIN_CONFIRMATIONS, owner_address=None, transfer_address=None,
                       fake_utxos=False):
    """
    Given a list of operations and a scatter/gather context,
    go prime it to fetch the cost of each operation.

    Operations must be a list containing 'preorder', 'register', 'update', 'transfer', 'revoke',
    'renewal', 'namespace_preorder', 'namespace_reveal', 'namespace_ready', or 'name_import'

    The scatter/gather context, when executed, will yield
    the following results:

        All operations will have:
        * "tx_fee": the transaction fee (including dust)
        * "insufficient": whether or not we had sufficient funds to calculate the tx_fee
        * "estimate": whether or not this is a rough estimate (i.e. if we don't have the payment info on hand)

        Preorder and Renewal will also have:
        * "name_cost": the cost of the name itself

        Namespace preorder will have:
        * "namespace_cost": the cost of the namespace

    Task results will be named after their operations.

    Return {'status': True} on success
    Return {'error': ...} on failure
    """

    from .nameops import (
        estimate_preorder_tx_fee, estimate_register_tx_fee,
        estimate_update_tx_fee, estimate_transfer_tx_fee,
        estimate_renewal_tx_fee, estimate_revoke_tx_fee,
        estimate_namespace_preorder_tx_fee, estimate_namespace_reveal_tx_fee,
        estimate_namespace_ready_tx_fee, estimate_name_import_tx_fee
    )

    name_operations = ['preorder', 'register', 'update', 'transfer', 'revoke', 'renewal']
    namespace_operations = ['namespace_preorder', 'namespace_reveal', 'namespace_ready', 'name_import']

    # sanity check...
    invalid_ops = []
    for op in operations:
        if op not in name_operations + namespace_operations:
            invalid_ops.append(op)

    if len(invalid_ops) > 0:
        return {'error': 'Invalid opeations: {}'.format(','.join(invalid_ops))}

    if payment_privkey_info is not None:
        payment_address = virtualchain.get_privkey_address(payment_privkey_info)

    if owner_privkey_info is not None:
        owner_address = virtualchain.get_privkey_address(owner_privkey_info)

    # fee estimation: cost of name_or_ns + cost of preorder transaction +
    # cost of registration transaction + cost of update transaction + cost of transfer transaction

    if owner_address:
        owner_address = virtualchain.address_reencode(str(owner_address))

    if payment_address:
        payment_address = virtualchain.address_reencode(str(payment_address))

    if transfer_address:
        transfer_address = virtualchain.address_reencode(str(transfer_address))

    assert owner_address, "Owner address or owner_privkey_info required"
    assert payment_address, "Payment address or payment_privkey_info required"
    if ('transfer' in operations or 'name_import' in operations) and (transfer_address is None or len(transfer_address) == 0):
        return {'error': 'Transfer or name import requested, but no recipient address given'}

    if len(set(operations).intersection(set(name_operations))) > 0 and len(set(operations).intersection(set(namespace_operations))) > 0:
        return {'error': 'Cannot mix name and namespace operations'}

    if len(operations) != len(set(operations)):
        return {'error': 'No duplicate operations allowed at this time'}

    # first things first: get UTXOs for owner and payment addresses
    utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

    if not fake_utxos:
        log.debug("Getting UTXOs for {}".format(owner_address))
        owner_utxos = get_utxos(owner_address, utxo_client=utxo_client, config_path=config_path, min_confirmations=min_payment_confs)
        if 'error' in owner_utxos:
            log.error("Failed to get UTXOs for {}: {}".format(owner_address, owner_utxos['error']))
            return {'error': 'Failed to get UTXOs for {}'.format(owner_address)}

        payment_utxos = get_utxos(payment_address, utxo_client=utxo_client, config_path=config_path, min_confirmations=min_payment_confs)
        if 'error' in payment_utxos:
            log.error("Failed to get UTXOs for {}: {}".format(payment_address, payment_utxos['error']))
            return {'error': 'Failed to get UTXOs for {}'.format(payment_address)}

        balance = sum([utxo.get('value', None) for utxo in payment_utxos])
        log.debug("Balance of {} is {} satoshis".format(payment_address, balance))
    else:
        log.debug("Forcing fake UTXOs")
        owner_utxos = []
        payment_utxos = []
        balance = 0

    estimated_owner_inputs = []
    estiamted_payment_inputs = []

    # find out what our UTXOs will look like for each operation
    if len(owner_utxos) > 0:
        estimated_owner_inputs = estimate_transaction_inputs(operations, owner_utxos, owner_address=owner_address)['inputs']
    else:
        # generate a fake owner input
        log.warning("Using a fake owner input")
        fake_owner_input = make_fake_input(owner_address)
        estimated_owner_inputs = [[fake_owner_input]] * len(operations)

    if len(payment_utxos) > 0:
        estimated_payment_inputs = estimate_transaction_inputs(operations, payment_utxos, payment_address=payment_address)['inputs']
    else:
        log.warning("Using a fake payment input")
        fake_payment_input = make_fake_input(payment_address)
        estimated_payment_inputs = [[fake_payment_input]] * len(operations)

    log.debug("Get total operation fees for running '{}' on {} owned by {} paid by {}".format(','.join(operations), name_or_ns, owner_address, payment_address))

    for i in xrange(0, len(operations)):
        if BLOCKSTACK_TEST:
            log.debug("Operation {} may consume owner inputs of {}\n{}".format(operations[i], owner_address, json.dumps(estimated_owner_inputs[i], indent=4, sort_keys=True)))
            log.debug("Operation {} may consume payment inputs of {}\n{}".format(operations[i], payment_address, json.dumps(estimated_payment_inputs[i], indent=4, sort_keys=True)))
        else:
            log.debug("Operation {} may consume up to {} owner inputs of {} and {} payment inputs of {}".format(
                operations[i], len(estimated_owner_inputs[i]), owner_address, len(estimated_payment_inputs[i]), payment_address
            ))

    def _get_balance():
        """
        get payment address balance (scatter/gather worker)
        """
        return {'status': balance, 'balance': balance}

    def _estimate_preorder_tx( operation_index ):
        """
        Estimate preorder tx cost
        Return {'status': True, 'name_cost': ..., 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        name_cost = None
        try:
            res = get_name_cost(name_or_ns, proxy=proxy)
            if 'error' in res:
                return {'error': 'Failed to get name cost'}

            name_cost = res['satoshis']
        except Exception as e:
            log.exception(e)
            return {'error': 'Could not get name price'}

        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

            insufficient_funds = False
            preorder_tx_fee = estimate_preorder_tx_fee(
                name_or_ns, name_cost, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client,
                payment_utxos=estimated_payment_inputs[operation_index], owner_address=owner_address,
                config_path=config_path, include_dust=True
            )

            if preorder_tx_fee is not None:
                preorder_tx_fee = int(preorder_tx_fee)
            else:
                # do our best
                preorder_tx_fee = (len('00' * APPROX_PREORDER_TX_LEN) * tx_fee_per_byte) / 2
                insufficient_funds = True

            return {'status': True, 'name_cost': name_cost, 'tx_fee': preorder_tx_fee, 'insufficient': insufficient_funds}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider for name preorder.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAME_PREORDER fee estimation.  Please try again.'}


    def _estimate_register_tx( operation_index ):
        """
        Estimate register tx cost
        Return {'status': True, 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        
        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

            insufficient_funds = False
            register_tx_fee = estimate_register_tx_fee(
                name_or_ns, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client,
                payment_utxos=estimated_payment_inputs[operation_index], owner_address=owner_address, zonefile_hash=zonefile_hash,
                config_path=config_path, include_dust=True
            )

            if register_tx_fee is not None:
                register_tx_fee = int(register_tx_fee)
            else:
                register_tx_fee = (len('00' * APPROX_REGISTER_TX_LEN) * tx_fee_per_byte) / 2
                insufficient_funds = True
            
            return {'status': True, 'tx_fee': register_tx_fee, 'insufficient': insufficient_funds}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider for name registration.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAME_REGISTRATION fee estimation.  Please try again.'}


    def _estimate_update_tx( operation_index ):
        """
        Estimate update tx fee
        Return {'status': True, 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

            insufficient_funds = False
            estimate = False
            update_tx_fee = estimate_update_tx_fee(
                name_or_ns, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client,
                payment_utxos=estimated_payment_inputs[operation_index], owner_utxos=estimated_owner_inputs[operation_index],
                config_path=config_path, include_dust=True
            )

            if update_tx_fee is not None:
                update_tx_fee = int(update_tx_fee)
            
            else:
                update_tx_fee = (len('00' * APPROX_UPDATE_TX_LEN) * tx_fee_per_byte) / 2
                insufficient_funds = True

            if payment_privkey_info is None:
                estimate = True

            return {'status': True, 'tx_fee': update_tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider for name update.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAME_UPDATE fee estimation.  Please try again.'}

    
    def _estimate_transfer_tx( operation_index ):
        """
        Estiamte transfer tx fee
        Return {'status': True, 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        if transfer_address is None or len(transfer_address) == 0:
            return {'error': 'No recipient address given'}

        try:

            if transfer_address is not None:
                utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

                insufficient_funds = False
                estimate = False

                transfer_tx_fee = estimate_transfer_tx_fee(
                    name_or_ns, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client,
                    payment_utxos=estimated_payment_inputs[operation_index], owner_utxos=estimated_owner_inputs[operation_index],
                    config_path=config_path, include_dust=True
                )
                
                if transfer_tx_fee is not None:
                    transfer_tx_fee = int(transfer_tx_fee)
                
                else:
                    transfer_tx_fee = (len('00' * APPROX_TRANSFER_TX_LEN) * tx_fee_per_byte) / 2
                    insufficient_funds = True

                if payment_privkey_info is None:
                    estimate = True

                return {'status': True, 'tx_fee': transfer_tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}
            
            else:
                return {'error': 'No transfer address'}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider for name transfer.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAME_TRANSFER fee estimation.  Please try again.'}


    def _estimate_revoke_tx( operation_index ):
        """
        Estimate revoke tx fee
        Return {'status': True, 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

            insufficient_funds = False
            estimate = False

            tx_fee = estimate_revoke_tx_fee(
                name_or_ns, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client,
                payment_utxos=estimated_payment_inputs[operation_index], owner_utxos=estimated_owner_inputs[operation_index],
                config_path=config_path, include_dust=True
            )

            if tx_fee is not None:
                tx_fee = int(tx_fee)
            
            else:
                tx_fee = (len('00' * APPROX_REVOKE_TX_LEN) * tx_fee_per_byte) / 2
                insufficient_funds = True

            if payment_privkey_info is None:
                estimate = True

            return {'status': True, 'tx_fee': tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider for name revoke.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAME_REVOKE fee estimation.  Please try again.'}


    def _estimate_renewal_tx( operation_index ):
        """
        Estimate renewal tx fee
        Return {'status': True, 'name_cost': ..., 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        name_cost = None
        try:
            res = get_name_cost(name_or_ns, proxy=proxy)
            name_cost = res['satoshis']
        except Exception as e:
            log.exception(e)
            return {'error': 'Could not get name price'}

        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

            insufficient_funds = False
            estimate = False

            tx_fee = estimate_renewal_tx_fee(
                name_or_ns, name_cost, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client, zonefile_hash=zonefile_hash,
                payment_utxos=estimated_payment_inputs[operation_index], owner_utxos=estimated_owner_inputs[operation_index],
                config_path=config_path, include_dust=True
            )

            if tx_fee is not None:
                tx_fee = int(tx_fee)
            
            else:
                tx_fee = (len('00' * APPROX_RENEWAL_TX_LEN) * tx_fee_per_byte) / 2
                insufficient_funds = True

            if payment_privkey_info is None:
                estimate = True

            return {'status': True, 'name_cost': name_cost, 'tx_fee': tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider for name renewal.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAME_RENEWAL fee estimation.  Please try again.'}


    def _estimate_namespace_preorder_tx( operation_index ):
        """
        Estimate namespace preorder tx fee
        Return {'status': True, 'namespace_cost': ..., 'tx_fee': ..., 'insufficient': ..., 'estimate': ...} on success
        Return {'error': ...} on failure
        """
        namespace_cost = None
        tx_fee = None
        insufficient_funds = False
        estimate = False

        try:
            res = get_namespace_cost(name_or_ns, proxy=proxy)
            namespace_cost = res['satoshis']
        except Exception as e:
            log.exception(e)
            return {'error': 'Could not get namespace price'}

        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

            log.debug("Estimate namespace preorder TX fee (from {})".format(payment_address))
            tx_fee = estimate_namespace_preorder_tx_fee( name_or_ns, namespace_cost, payment_privkey_info, tx_fee_per_byte, utxo_client, 
                                     payment_utxos=estimated_payment_inputs[operation_index],
                                     config_path=config_path, include_dust=True )
            
            if tx_fee is not None:
                tx_fee = int(tx_fee)

            else:
                tx_fee = (len('00' * APPROX_NAMESPACE_PREORDER_TX_LEN) * tx_fee_per_byte) / 2
                insufficient_funds = True

            return {'status': True, 'namespace_cost': namespace_cost, 'tx_fee': tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error("Failed to query UTXO provider for namespace preorder.")
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAMESPACE_PREORDER fee estimation.  Please try again.'}


    def _estimate_namespace_reveal_tx( operation_index ):
        """
        Estimate namespace reveal tx fee
        payment_address here corresponds to the NAMESPACE_PREORDER key's address
        Return {'status': True, 'tx_fee': ..., 'insufficient': .., 'estimate': ...} on success
        Return {'error': ...} on failure
        """
        tx_fee = None
        insufficient_funds = False
        estimate = False

        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

            log.debug("Estimate namespace reveal TX fee (from {})".format(payment_address))
            tx_fee = estimate_namespace_reveal_tx_fee( name_or_ns, payment_privkey_info, tx_fee_per_byte, utxo_client, 
                                     payment_utxos=estimated_payment_inputs[operation_index],
                                     config_path=config_path, include_dust=True )

            if tx_fee is not None:
                tx_fee = int(tx_fee)

            else:
                tx_fee = (len('00' * APPROX_NAMESPACE_REVEAL_TX_LEN) * tx_fee_per_byte) / 2
                insufficient_funds = True

            return {'status': True, 'tx_fee': tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error("Failed to query UTXO provider for namespace reveal.")
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAMESPACE_REVEAL fee estimation.  Please try again.'}


    def _estimate_namespace_ready_tx( operation_index ):
        """
        Estimate namespace ready tx fee
        payment_address here corresponds to the reveal address (i.e. the reveal key pays for the NAMESPACE_READY)
        Return {'status': True, 'tx_fee': ..., 'insufficient': ..., 'estimate': ...} on success
        Return {'error': ...} on failure
        """
        tx_fee = None
        insufficient_funds = False
        estimate = False

        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)

            log.debug("Estimate namespace ready TX fee (from {})".format(payment_address))
            tx_fee = estimate_namespace_ready_tx_fee( name_or_ns, payment_privkey_info, tx_fee_per_byte, utxo_client,
                                    revealer_utxos=estimated_payment_inputs[operation_index],
                                    config_path=config_path, include_dust=True )
            
            if tx_fee is not None:
                tx_fee = int(tx_fee)

            else:
                tx_fee = (len('00' * APPROX_NAMESPACE_READY_TX_LEN) * tx_fee_per_byte) / 2
                insufficient_funds = True

            return {'status': True, 'tx_fee': tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error("Failed to query UTXO provider for namespace ready")
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAMESPACE_READY fee estimation.  Please try again'}


    def _estimate_name_import_tx( operation_index ):
        """
        Estimate name import tx fee
        payment_address is address of the derived reveal key used to issue the import
        Return {'status': True, 'tx_fee': ..., 'insufficient': ..., 'estimate': ...} on success
        Return {'error': ...} on failure
        """
        tx_fee = None
        insufficient_funds = False
        estimate = False

        if transfer_address is None or len(transfer_address) == 0:
            return {'error': 'No recipient address given'}

        try:
            utxo_client = get_utxo_provider_client(config_path=config_path, min_confirmations=min_payment_confs)
            tx_fee = estimate_name_import_tx_fee( name_or_ns, payment_privkey_info, transfer_address, tx_fee_per_byte, utxo_client, 
                                    importer_utxos=estimated_payment_inputs[operation_index],
                                    config_path=config_path, include_dust=True )

            if tx_fee is not None:
                tx_fee = int(tx_fee)

            else:
                return {'error' : 'Failed to get good estimate of name import tx fee, and ' + 
                        'there is no fallback estimation'}

            return {'status': True, 'tx_fee': tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error("Failed to query UTXO provider for name import.")
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider for NAME_IMPORT fee estimation.  Please try again'}


    sg = scatter_gather
    assert sg

    tx_fee_checks = {
        'preorder': _estimate_preorder_tx,
        'register': _estimate_register_tx,
        'update': _estimate_update_tx,
        'transfer': _estimate_transfer_tx,
        'revoke': _estimate_revoke_tx,
        'renewal': _estimate_renewal_tx,
        'namespace_preorder': _estimate_namespace_preorder_tx,
        'namespace_reveal': _estimate_namespace_reveal_tx,
        'namespace_ready': _estimate_namespace_ready_tx,
        'name_import': _estimate_name_import_tx
    }

    sg.add_task('get_balance', _get_balance)

    # queue each operation
    for i in xrange(0, len(operations)):
        op = operations[i]
        if op not in tx_fee_checks.keys():
            log.error("Unrecognized operation {}".format(op))
            return {'error': 'Unrecognized operation'}

        check_name = '{}_tx_fee'.format(op)

        log.debug("Add task {} ({})".format(check_name, tx_fee_checks[op]))

        check_func = functools.partial(tx_fee_checks[op], i)
        sg.add_task( check_name, check_func )

    # scatter/gather primed!
    return {'status': True}


def interpret_operation_fees( operations, scatter_gather, balance=None ):
    """
    Interpret the result of getting the tx fees required for
    a sequence of operations.  Coalesce them into a grand total,
    and warn us if there is not enough balance to cover the cost.

    Return a dict with the following:
        * preorder_tx_fee
        * register_tx_fee
        * update_tx_fee
        * transfer_tx_fee
        * renewal_tx_fee
        * revoke_tx_fee
        * namespace_preorder_tx_fee
        * namespace_reveal_tx_fee
        * namespace_ready_tx_fee
        * name_import_tx_fee
        * name_price
        * namespace_price
        * total_estimated_cost
        * warnings
    Return {'error': ...} if an operation failed
    """

    insufficient_funds = False
    estimate = False
    total_cost = 0
    total_tx_fees = 0
    reply = {}

    results = scatter_gather.get_results()

    if balance is None:
        # extract from running operation sanity checks
        assert 'get_balance' in results
        balance = 0
        if 'error' in results['get_balance'].keys():
            log.error("Failed to get balance")
        
        else:
            balance = results['get_balance']['balance']
            log.debug("Balance is {} satoshis".format(balance))

    failed_tasks = []
    failed_task_errors = []

    for task in operations:
        tx_fee_task = '{}_tx_fee'.format(task)
        task_res = results[tx_fee_task]
        if 'error' in task_res:
            failed_tasks.append(tx_fee_task)
            failed_task_errors.append(task_res['error'])
            continue

        assert 'insufficient' in task_res, "Invalid task res: {}".format(task_res)
        assert 'tx_fee' in task_res, "Invalid task res: {}".format(task_res)

        if task_res['tx_fee'] is None:
            log.error("Task {} failed to get tx fee".format(task))
            failed_tasks.append(tx_fee_task)
            failed_task_errors.append("Could not calculate transaction fee")
            continue

        insufficient_funds = insufficient_funds or task_res['insufficient']
        estimate = estimate or task_res.get('estimate', False)

        reply[tx_fee_task] = int(task_res['tx_fee'])
        total_tx_fees += int(task_res['tx_fee'])

        log.debug("{} +{} satoshis (tx fee)".format(tx_fee_task, int(task_res['tx_fee'])))
        total_cost += int(task_res['tx_fee'])

        if 'name_cost' in task_res.keys():
            log.debug("{} +{} satoshis (name cost)".format(tx_fee_task, int(task_res['name_cost'])))
            total_cost += int(task_res['name_cost'])
            reply['name_price'] = int(task_res['name_cost'])

        if 'namespace_cost' in task_res.keys():
            log.debug("{} +{} satoshis (namespace cost)".format(tx_fee_task, int(task_res['namespace_cost'])))
            total_cost += int(task_res['namespace_cost'])
            reply['namespace_price'] = int(task_res['namespace_cost'])


    log.debug('Total cost of {} is {} satoshis'.format(','.join(operations), total_cost))

    reply['total_tx_fees'] = total_tx_fees
    reply['total_estimated_cost'] = total_cost
    if total_cost > balance:
        log.debug("Insufficient funds: need {}, have {}".format(total_cost, balance))
        insufficient_funds = True

    if insufficient_funds:
        reply['warnings'] = ['Insufficient funds (need {}, have {}).  Fees are rough estimates.'.format(total_cost, balance)]

    if estimate:
        reply.setdefault('warnings', [])
        reply['warnings'].append('Wallet not accessed; fees are rough estimates.')

    if len(failed_tasks) > 0:
        error_messages = ",".join( ["{} ({})".format(task, err) for task, err in zip(failed_tasks, failed_task_errors)] )
        log.error("Some fee-query tasks failed: {}".format(error_messages))
        reply['error'] = 'Some fee-query tasks failed: {}'.format(error_messages)

    return reply


def check_operations( fqu_or_ns, operations, owner_privkey_info, payment_privkey_info, required_checks=[], burn_address=None, 
                      transfer_address=None, owner_address=None, zonefile_hash=None, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that an operation sequence can be performed, given the set of sanity checks that must pass.
    Return {'status': True, 'opchecks': {...}} if so
    Return {'error': ...} if not.
    """
    
    assert len(required_checks) > 0, "Missing required checks"

    log.debug("Check {} on {}: test {}".format(', '.join(operations), fqu_or_ns, ', '.join(required_checks)))

    payment_address = virtualchain.get_privkey_address(payment_privkey_info)
    
    # first things first: get fee per byte 
    tx_fee_per_byte = virtualchain.get_tx_fee_per_byte(config_path=config_path)
    if tx_fee_per_byte is None:
        log.error("Unable to calculate fee per byte")
        return {'error': 'Unable to get fee estimate'}

    sg = ScatterGather()

    res = operation_sanity_checks(fqu_or_ns, operations, sg, payment_privkey_info, owner_privkey_info, tx_fee_per_byte,
                                  required_checks=required_checks, owner_address=owner_address, burn_address=burn_address, zonefile_hash=zonefile_hash,
                                  min_confirmations=min_payment_confs, config_path=config_path,
                                  transfer_address=transfer_address, proxy=proxy )

    if 'error' in res:
        log.error("Failed to begin operation sanity checks: {}".format(res['error']))
        return {'error': 'Failed to perform sanity checks', 'tx_fee_per_byte': tx_fee_per_byte}

    sg.run_tasks()

    opchecks = interpret_operation_sanity_checks( operations, sg )
    if 'error' in opchecks:
        log.error("Failed to interpret operation sanity checks")
        return {'error': 'Failed operation sanity checks:\n{}'.format(opchecks['error']), 'opchecks': opchecks, 'tx_fee_per_byte': tx_fee_per_byte}

    failed_checks = []
    failed_check_errors = {}
    for res_name in required_checks + ['get_balance']:
        if 'error' in sg.get_result(res_name):
            log.debug("Task '{}' reports error: {}".format(res_name, sg.get_result(res_name)['error']))
            failed_checks.append(res_name)
            failed_check_errors[res_name] = 'Reason: {}'.format(sg.get_result(res_name)['error'])

        if not sg.get_result(res_name)['status']:
            log.debug("Task '{}' did not succeed".format(res_name))
            failed_checks.append(res_name)
            failed_check_errors[res_name] = ''

    if len(failed_checks) > 0:
        return {'error': 'Unable to {} name:\n{}'.format(
                    ','.join(operations),
                    '\n'.join(['  * check "{}" failed.  {}'.format(check, failed_check_errors.get(res_name, "")) for check in failed_checks])
                ),
                'opchecks': opchecks,
                'tx_fee_per_byte': tx_fee_per_byte}

    balance = sg.get_result('get_balance')['balance']

    if balance < opchecks['total_estimated_cost']:
        msg = 'Address {} does not have enough balance (need {}, have {}).'
        msg = msg.format(payment_address, opchecks['total_estimated_cost'], balance)
        return {'error': msg, 'opchecks': opchecks, 'tx_fee_per_byte': tx_fee_per_byte}

    # checks pass!
    return {'status': True, 'opchecks': opchecks, 'tx_fee_per_byte': tx_fee_per_byte}


def _check_op(fqu_or_ns, operation, required_checks, owner_privkey_info, payment_privkey_info,
              owner_address=None, transfer_address=None, zonefile_hash=None, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Check an operation
    Return {'status': True, 'opchecks': {...}, 'tx_fee': ...} on success
    Return {'error': ...} on error
    """
    # find tx fee, and do sanity checks
    assert payment_privkey_info

    res = check_operations( fqu_or_ns, [operation], owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs,
                            transfer_address=transfer_address, owner_address=owner_address, zonefile_hash=zonefile_hash,
                            required_checks=required_checks, config_path=config_path, proxy=proxy )

    opchecks = res.get('opchecks', None)
    tx_fee_per_byte = res.get('tx_fee_per_byte', None)
    tx_fee = None

    if opchecks:
        tx_fee = opchecks.get('total_tx_fees', None)

    if 'error' in res:
        return {'error': res['error'], 'tx_fee': tx_fee, 'tx_fee_per_byte': tx_fee_per_byte, 'opchecks': opchecks}

    else:
        return {'status': True, 'tx_fee': tx_fee, 'tx_fee_per_byte': tx_fee_per_byte, 'opchecks': opchecks}


def check_preorder(fqu, cost_satoshis, owner_privkey_info, payment_privkey_info, owner_address=None, burn_address=None, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a preorder can go through.

    Return {'status': True, 'opchecks': {...}, 'tx_fee': ...}
    """

    # find tx fee, and do sanity checks
    assert owner_privkey_info
    assert payment_privkey_info

    required_checks = ['is_name_available', 'is_payment_address_usable', 'is_burn_address_correct']

    res = check_operations( fqu, ['preorder'], owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs, burn_address=burn_address, owner_address=owner_address,
                            required_checks=required_checks, config_path=config_path, proxy=proxy )

    opchecks = res.get('opchecks', None)
    tx_fee = None
    tx_fee_per_byte = None

    if opchecks:
        tx_fee = opchecks.get('total_tx_fees', None)
        tx_fee_per_byte = opchecks.get('tx_fee_per_byte', None)

    if 'error' in res:
        return {'error': res['error'], 'opchecks': res.get('opchecks', None), 'tx_fee': res.get('opchecks', {}).get('total_tx_fees', None), 'tx_fee_per_byte': tx_fee_per_byte}

    if cost_satoshis is not None:
        if opchecks['name_price'] > cost_satoshis:
            return {'error': 'Invalid cost: expected {}, got {}'.format(opchecks['name_price'], cost_satoshis), 'tx_fee': tx_fee, 'tx_fee_per_byte': tx_fee_per_byte, 'opchecks': opchecks}

    return {'status': True, 'tx_fee': tx_fee, 'tx_fee_per_byte': tx_fee_per_byte, 'opchecks': opchecks}


def check_register(fqu, owner_privkey_info, payment_privkey_info, owner_address=None, zonefile_hash=None, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None, force_it=False ):
    """
    Verify that a register can go through
    """
    required_checks = ['is_name_available', 'is_payment_address_usable', 'register_can_change_zonefile_hash']
    if not force_it:
        required_checks += ['owner_can_receive']
    return _check_op(fqu, 'register', required_checks, owner_privkey_info, payment_privkey_info,
            owner_address=owner_address, zonefile_hash=zonefile_hash, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy )


def check_update(fqu, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None, force_it=False ):
    """
    Verify that an update can go through
    """
    required_checks = ['is_payment_address_usable']
    if not force_it:
        required_checks += ['is_name_registered', 'is_owner_address_usable', 'is_name_owner', 'is_name_outside_grace_period']

    return _check_op(fqu, 'update', required_checks, owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy)


def check_transfer(fqu, transfer_address, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a transfer can go through
    """
    required_checks = ['is_name_registered', 'is_owner_address_usable', 'is_payment_address_usable', 'is_name_owner', 'recipient_can_receive', 'is_name_outside_grace_period']

    return _check_op(fqu, 'transfer', required_checks, owner_privkey_info, payment_privkey_info, transfer_address=transfer_address, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy)


def check_renewal(fqu, renewal_fee, owner_privkey_info, payment_privkey_info, zonefile_hash=None, new_owner_address=None, burn_address=None, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a renew can go through
    """ 
    # find tx fee, and do sanity checks
    assert owner_privkey_info
    assert payment_privkey_info
    
    if new_owner_address is None:
        new_owner_address = virtualchain.get_privkey_address(owner_privkey_info)

    required_checks = ['is_name_registered', 'is_name_owner', 'is_owner_address_usable', 'is_payment_address_usable', 
                       'recipient_can_receive', 'renewal_can_change_zonefile_hash', 'renewal_can_change_owner_address',
                       'is_burn_address_correct']

    res = check_operations( fqu, ['renewal'], owner_privkey_info, payment_privkey_info, zonefile_hash=zonefile_hash, transfer_address=new_owner_address, min_payment_confs=min_payment_confs, burn_address=burn_address,
                            required_checks=required_checks, config_path=config_path, proxy=proxy )

    opchecks = res.get('opchecks', None)
    tx_fee_per_byte = res.get('tx_fee_per_byte', None)
    tx_fee = None

    if opchecks:
        tx_fee = opchecks.get('total_tx_fees', None)

    if 'error' in res:
        return {'error': res['error'], 'opchecks': res.get('opchecks', None), 'tx_fee': res.get('opchecks', {}).get('total_tx_fees', None), 'tx_fee_per_byte': tx_fee_per_byte}

    if renewal_fee is not None:
        if opchecks['name_price'] > renewal_fee:
            return {'error': 'Invalid cost: expected {}, got {}'.format(opchecks['name_price'], renewal_fee), 'tx_fee': tx_fee, 'tx_fee_per_byte': tx_fee_per_byte, 'opchecks': opchecks}

    return {'status': True, 'tx_fee': tx_fee, 'tx_fee_per_byte': tx_fee_per_byte, 'opchecks': opchecks}


def check_revoke(fqu, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a revoke can go through
    """
    required_checks = ['is_name_registered', 'is_name_owner', 'is_owner_address_usable', 'is_payment_address_usable', 'is_name_outside_grace_period']
    return _check_op(fqu, 'revoke', required_checks, owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy )


def check_namespace_preorder(nsid, payment_privkey_info, reveal_address, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a namespace preorder can go through
    @payment_privkey_info is the private key information for the payment private key (that will pay the namespace cost and both the preorder and reveal fees)
    @reveal_address is the address of the reveal key (but will be treated as the "owner" address by the op-checker)
    """
    required_checks = ['is_namespace_available', 'is_payment_address_usable', 'is_namespace_reveal_address_valid']
    return _check_op(nsid, 'namespace_preorder', required_checks, None, payment_privkey_info, owner_address=reveal_address, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy)


def check_namespace_reveal(nsid, payment_privkey_info, reveal_address, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a namespace reveal can go through
    @payment_privkey_info is the private key information for the payment private key (that will pay for the tx fee)
    @reveal_address is the address of the reveal key (but will be treated as the "owner" address by the op-checker)
    """
    required_checks = ['is_namespace_available', 'is_payment_address_usable', 'is_namespace_reveal_address_valid']
    return _check_op(nsid, 'namespace_reveal', required_checks, None, payment_privkey_info, owner_address=reveal_address, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy )


def check_namespace_ready(nsid, reveal_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a namespace ready can go through
    @reveal_privkey_info is the private key information for the reveal private key (but will be treated as the "payment" key for the op-checker)
    """
    required_checks = ['is_namespace_reveal_address_valid', 'is_namespace_revealer', 'is_namespace_still_revealed', 'is_payment_address_usable']
    reveal_addr = virtualchain.get_privkey_address(reveal_privkey_info)
    return _check_op(nsid, 'namespace_ready', required_checks, None, reveal_privkey_info, owner_address=reveal_addr, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy)


def check_name_import(name, importer_privkey_info, recipient_address, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a name import can go through
    @importer_privkey_info is the private key information derived from the reveal private key.  It will be used as the "payment" key by the op-checker
    """
    required_checks = ['is_namespace_still_revealed', 'is_payment_address_usable', 'is_owner_address_usable', 'is_name_import_key', 'recipient_can_receive']
    return _check_op(name, 'name_import', required_checks, importer_privkey_info, importer_privkey_info, transfer_address=recipient_address, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy)

