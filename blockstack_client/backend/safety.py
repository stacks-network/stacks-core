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

import os
import sys 
import threading

from ..constants import *
from ..keys import *
from ..proxy import *
from ..config import get_logger, get_utxo_provider_client

from .blockchain import (
    get_balance, is_address_usable, get_utxos,
    can_receive_name, get_tx_confirmations, get_tx_fee
)

from ..scripts import UTXOException, is_name_valid

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
            'Names may only contain alphanumeric characters, '
            'dashes, and underscores.'
        )

        return msg

    return 'The name is invalid'


class ScatterGatherThread(threading.Thread):
    """
    Scatter/gatter thread worker
    Useful for doing long-running queries in parallel
    """
    def __init__(self, rpc_call):
        threading.Thread.__init__(self)
        self.rpc_call = rpc_call
        self.result = None
        self.has_result = False
        self.result_mux = threading.Lock()
        self.result_mux.acquire()


    def get_result(self):
        """
        Wait for data and get it
        """
        self.result_mux.acquire()
        res = self.result
        self.result_mux.release()
        return res


    def post_result(self, res):
        """
        Give back result and release
        """
        if self.has_result:
            return 

        self.has_result = True
        self.result = res
        self.result_mux.release()
        return


    @classmethod
    def do_work(cls, rpc_call):
        """
        Run the given RPC call and post the result
        """
        try:
            log.debug("Run task {}".format(rpc_call))
            res = rpc_call()
            log.debug("Task exit {}".format(rpc_call))
            return res

        except Exception as e:
            log.exception(e)
            log.debug("Task exit {}".format(rpc_call))
            return {'error': 'Task encountered a fatal exception:\n{}'.format(traceback.format_exc())}


    def run(self):
        res = ScatterGatherThread.do_work(self.rpc_call)
        self.post_result(res)


class ScatterGather(object):
    """
    Scatter/gather work pool
    Give it a few tasks, and it will run them
    in parallel
    """
    def __init__(self):
        self.tasks = {}
        self.ran = False
        self.results = {}

    def add_task(self, result_name, rpc_call):
        assert result_name not in self.tasks.keys(), "Duplicate task: {}".format(result_name)
        self.tasks[result_name] = rpc_call


    def get_result(self, result_name):
        assert self.ran
        assert result_name in self.results, "Missing task: {}".format(result_name)
        return self.results[result_name]


    def get_results(self):
        """
        Get the set of results
        """
        assert self.ran
        return self.results


    def run_tasks(self, single_thread=False):
        """
        Run all queued tasks, wait for them all to finish,
        and return the set of results
        """
        if not single_thread:
            threads = {}
            for task_name, task_call in self.tasks.items():
                log.debug("Start task '{}'".format(task_name))
                thr = ScatterGatherThread(task_call)
                thr.start()

                threads[task_name] = thr

            for task_name, thr in threads.items():
                log.debug("Join task '{}'".format(task_name))
                thr.join()
                res = thr.get_result()
                self.results[task_name] = res
               
        else:
            # for testing purposes
            for task_name, task_call in self.tasks.items():
                res = ScatterGatherThread.do_work(task_call)
                self.results[task_name] = res

        self.ran = True
        return self.results


def operation_sanity_checks(fqu, operations, scatter_gather, payment_privkey_info, owner_privkey_info, required_checks=[],
                            min_confirmations=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH,
                            transfer_address=None, proxy=None):
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

    Return {'status': True} on success
    Return {'error': ...} on error
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if proxy is None:
        proxy = get_default_proxy(config_path)

    owner_address = get_privkey_info_address(owner_privkey_info)
    payment_address = get_privkey_info_address(payment_privkey_info)
    if transfer_address:
        transfer_address = str(transfer_address)
    
    sg = scatter_gather

    def _is_name_available():
        """
        is name available? (scatter/gather worker)
        """
        if is_name_registered(fqu, proxy=proxy):
            return {'error': '{} is already registered.'.format(fqu)}
        else:
            return {'status': True}

    def _is_name_registered():
        """
        is name taken already? (scatter/gather worker)
        """
        if not is_name_registered(fqu, proxy=proxy):
            return {'error': '{} is not registered.'.format(fqu)}
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
        if not is_address_usable(addr, config_path=config_path, min_confirmations=min_confirmations):
            msg = (
                'Address {} has insufficiently confirmed transactions. '
                'Wait and try later.'
            )
            msg = msg.format(addr)
            return {'error': msg}

        else:
            return {'status': True}

    def _is_name_owner(addr):
        """
        Is the given address the name owner?
        """
        res = get_names_owned_by_address(addr, proxy=proxy)
        if 'error' in res:
            return {'error': res['error']}

        else:
            return {'status': fqu in res}

    
    check_names = {
        'is_owner_address_usable': lambda: _is_address_usable(owner_address),
        'is_payment_address_usable': lambda: _is_address_usable(payment_address),
        'is_name_available': _is_name_available,
        'owner_can_receive': lambda: _can_receive_name(owner_address),
        'is_name_registered': _is_name_registered,
        'is_name_owner': lambda: _is_name_owner(owner_address),
        'recipient_can_receive': lambda: _can_receive_name(transfer_address),
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
    res = get_operation_fees(fqu, operations, sg, payment_privkey_info, owner_privkey_info,
                             payment_address=payment_address, owner_address=owner_address, transfer_address=transfer_address,
                             min_payment_confs=min_confirmations, config_path=config_path, proxy=proxy )

    if 'error' in res:
        log.error("Failed to get operation fees: {}".format(res['error']))
        return {'error': 'Failed to calculate transaction fees'}

    log.debug("Queued tasks for {} on {}: {}".format(', '.join(operations), fqu, ', '.join(sorted(sg.tasks.keys()))))

    # scatter/gather primed!
    return {'status': True}


def interpret_operation_sanity_checks( name, operations, scatter_gather ):
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


def get_operation_fees(name, operations, scatter_gather, payment_privkey_info, owner_privkey_info,
                       proxy=None, config_path=CONFIG_PATH, payment_address=None,
                       min_payment_confs=TX_MIN_CONFIRMATIONS, owner_address=None, transfer_address=None):
    """
    Given a list of operations and a scatter/gather context,
    go prime it to fetch the cost of each operation.
    
    Operations must be a list containing 'preorder', 'register', 'update', 'transfer', 'revoke', or 'renewal'

    The scatter/gather context, when executed, will yield
    the following results:

        All operations will have:
        * "tx_fee": the transaction fee (including dust)
        * "insufficient": whether or not we had sufficient funds to calculate the tx_fee
        * "estimate": whether or not this is a rough estimate (i.e. if we don't have the payment info on hand)
    
        Preorder and Renewal will also have:
        * "name_cost": the cost of the name itself

    Task results will be named after their operations.

    Return {'status': True} on success
    Return {'error': ...} on failure
    Raise on invalid argument
    """

    from .nameops import (
        estimate_preorder_tx_fee, estimate_register_tx_fee,
        estimate_update_tx_fee, estimate_transfer_tx_fee,
        estimate_renewal_tx_fee, estimate_revoke_tx_fee
    )

    if payment_privkey_info is not None:
        payment_address = get_privkey_info_address(payment_privkey_info)

    if owner_privkey_info is not None:
        owner_address = get_privkey_info_address(owner_privkey_info)

    # fee estimation: cost of name + cost of preorder transaction +
    # cost of registration transaction + cost of update transaction + cost of transfer transaction

    reply = {}
    
    if owner_address:
        owner_address = str(owner_address)
    if payment_address:
        payment_address = str(payment_address)
    if transfer_address:
        transfer_address = str(transfer_address)

    assert owner_address, "Owner address or owner_privkey_info required"
    assert payment_address, "Payment address or payment_privkey_info required"
    if 'transfer' in operations:
        assert transfer_address, "Transfer address required"

    log.debug("Get total operation fees for running '{}' on {} owned by {} paid by {}".format(','.join(operations), name, owner_address, payment_address))

    def _get_balance():
        """
        get payment address balance (scatter/gather worker)
        """
        balance = get_balance(payment_address, config_path=config_path)
        if balance is None:
            msg = 'Failed to get balance'
            return {'error': msg}
        else:
            return {'status': balance}

    def _estimate_preorder_tx():
        """
        Estimate preorder tx cost
        Return {'status': True, 'name_cost': ..., 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        name_cost = None
        try:
            res = get_name_cost(name, proxy=proxy)
            if 'error' in res:
                return {'error': 'Failed to get name cost'}

            name_cost = res['satoshis']
        except Exception as e:
            log.exception(e)
            return {'error': 'Could not get name price'}

        try:
            owner_privkey_params = get_privkey_info_params(owner_privkey_info)
            utxo_client = get_utxo_provider_client(config_path=config_path)

            insufficient_funds = False
            preorder_tx_fee = estimate_preorder_tx_fee(
                name, name_cost, owner_address, payment_address, utxo_client,
                owner_privkey_params=owner_privkey_params, min_payment_confs=min_payment_confs,
                config_path=config_path, include_dust=True
            )

            if preorder_tx_fee is not None:
                preorder_tx_fee = int(preorder_tx_fee)
            else:
                # do our best
                preorder_tx_fee = get_tx_fee('00' * APPROX_PREORDER_TX_LEN, config_path=config_path)
                insufficient_funds = True

            return {'status': True, 'name_cost': name_cost, 'tx_fee': preorder_tx_fee, 'insufficient': insufficient_funds}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider.  Please try again.'}


    def _estimate_register_tx():
        """
        Estimate register tx cost
        Return {'status': True, 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        
        try:
            owner_privkey_params = get_privkey_info_params(owner_privkey_info)
            utxo_client = get_utxo_provider_client(config_path=config_path)

            insufficient_funds = False
            register_tx_fee = estimate_register_tx_fee(
                name, owner_address, payment_address, utxo_client,
                owner_privkey_params=owner_privkey_params,
                config_path=config_path, include_dust=True
            )

            if register_tx_fee is not None:
                register_tx_fee = int(register_tx_fee)
            else:
                register_tx_fee = get_tx_fee('00' * APPROX_REGISTER_TX_LEN, config_path=config_path)
                insufficient_funds = True
            
            return {'status': True, 'tx_fee': register_tx_fee, 'insufficient': insufficient_funds}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider.  Please try again.'}


    def _estimate_update_tx():
        """
        Estimate update tx fee
        Return {'status': True, 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        try:
            owner_privkey_params = get_privkey_info_params(owner_privkey_info)
            utxo_client = get_utxo_provider_client(config_path=config_path)

            insufficient_funds = False
            estimate = False
            update_tx_fee = estimate_update_tx_fee(
                name, payment_privkey_info, owner_address, utxo_client,
                owner_privkey_params=owner_privkey_params,
                config_path=config_path, payment_address=payment_address, include_dust=True
            )

            if update_tx_fee is not None:
                update_tx_fee = int(update_tx_fee)
            
            else:
                update_tx_fee = get_tx_fee('00' * APPROX_UPDATE_TX_LEN, config_path=config_path)
                insufficient_funds = True

            if payment_privkey_info is None:
                estimate = True

            return {'status': True, 'tx_fee': update_tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider.  Please try again.'}

    
    def _estimate_transfer_tx():
        """
        Estiamte transfer tx fee
        Return {'status': True, 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        try:

            if transfer_address is not None:
                owner_privkey_params = get_privkey_info_params(owner_privkey_info)
                utxo_client = get_utxo_provider_client(config_path=config_path)

                insufficient_funds = False
                estimate = False

                transfer_tx_fee = estimate_transfer_tx_fee(
                    name, payment_privkey_info, owner_address, utxo_client,
                    owner_privkey_params=owner_privkey_params,
                    config_path=config_path, payment_address=payment_address, include_dust=True
                )
                
                if transfer_tx_fee is not None:
                    transfer_tx_fee = int(transfer_tx_fee)
                
                else:
                    transfer_tx_fee = get_tx_fee('00' * APPROX_TRANSFER_TX_LEN, config_path=config_path)
                    insufficient_funds = True

                if payment_privkey_info is None:
                    estimate = True

                return {'status': True, 'tx_fee': transfer_tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}
            
            else:
                return {'error': 'No transfer address'}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider.  Please try again.'}


    def _estimate_revoke_tx():
        """
        Estimate revoke tx fee
        Return {'status': True, 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        try:
            owner_privkey_params = get_privkey_info_params(owner_privkey_info)
            utxo_client = get_utxo_provider_client(config_path=config_path)

            insufficient_funds = False
            estimate = False

            tx_fee = estimate_revoke_tx_fee(
                name, payment_privkey_info, owner_address, utxo_client,
                owner_privkey_params=owner_privkey_params,
                config_path=config_path, include_dust=True
            )

            if tx_fee is not None:
                tx_fee = int(tx_fee)
            
            else:
                tx_fee = get_tx_fee('00' * APPROX_REVOKE_TX_LEN, config_path=config_path)
                insufficient_funds = True

            if payment_privkey_info is None:
                estimate = True

            return {'status': True, 'tx_fee': tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider.  Please try again.'}


    def _estimate_renewal_tx():
        """
        Estimate renewal tx fee
        Return {'status': True, 'name_cost': ..., 'tx_fee': ..., 'insufficient': ...} on success
        Return {'error': ...} on failure
        """
        name_cost = None
        try:
            res = get_name_cost(name, proxy=proxy)
            name_cost = res['satoshis']
        except Exception as e:
            log.exception(e)
            return {'error': 'Could not get name price'}

        try:
            owner_privkey_params = get_privkey_info_params(owner_privkey_info)
            utxo_client = get_utxo_provider_client(config_path=config_path)

            insufficient_funds = False
            estimate = False

            tx_fee = estimate_renewal_tx_fee(
                name, name_cost, payment_privkey_info, owner_privkey_info, utxo_client,
                config_path=config_path, include_dust=True
            )

            if tx_fee is not None:
                tx_fee = int(tx_fee)
            
            else:
                tx_fee = get_tx_fee('00' * APPROX_RENEWAL_TX_LEN, config_path=config_path)
                insufficient_funds = True

            if payment_privkey_info is None:
                estimate = True

            return {'status': True, 'name_cost': name_cost, 'tx_fee': tx_fee, 'insufficient': insufficient_funds, 'estimate': estimate}

        except UTXOException as ue:
            log.error('Failed to query UTXO provider.')
            if BLOCKSTACK_DEBUG is not None:
                log.exception(ue)

            return {'error': 'Failed to query UTXO provider.  Please try again.'}

    sg = scatter_gather
    assert sg

    tx_fee_checks = {
        'preorder': _estimate_preorder_tx,
        'register': _estimate_register_tx,
        'update': _estimate_update_tx,
        'transfer': _estimate_transfer_tx,
        'revoke': _estimate_revoke_tx,
        'renewal': _estimate_renewal_tx,
    }

    sg.add_task('get_balance', _get_balance)

    # queue each operation
    for op in set(operations):

        if op not in tx_fee_checks.keys():
            log.error("Unrecognized operation {}".format(op))
            return {'error': 'Unrecognized operation'}

        check_name = '{}_tx_fee'.format(op)
        sg.add_task( check_name, tx_fee_checks[op] )

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
        * name_price
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
            balance = results['get_balance']['status']
            log.debug("Balance is {} satoshis".format(balance))

    failed_tasks = []
    for task in operations:
        tx_fee_task = '{}_tx_fee'.format(task)
        task_res = results[tx_fee_task]
        if 'error' in task_res:
            failed_tasks.append(tx_fee_task)
            continue

        assert 'insufficient' in task_res, "Invalid task res: {}".format(task_res)
        assert 'tx_fee' in task_res, "Invalid task res: {}".format(task_res)

        if task_res['tx_fee'] is None:
            log.error("Task {} failed to get tx fee".format(task))
            failed_tasks.append(tx_fee_task)
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

    log.debug('Total cost of {} is {} satoshis'.format(','.join(operations), total_cost))

    reply['total_tx_fees'] = total_tx_fees
    reply['total_estimated_cost'] = total_cost
    if total_cost > balance:
        log.debug("Insufficient funds: need {}, have {}".format(total_cost, balance))
        insufficient_funds = True

    if insufficient_funds:
        reply['warnings'] = ['Insufficient funds; fees are rough estimates.']

    if estimate:
        reply.setdefault('warnings', [])
        reply['warnings'].append('Wallet not accessed; fees are rough estimates.')

    if len(failed_tasks) > 0:
        log.error("Some fee-query tasks failed: {}".format(','.join(failed_tasks)))
        reply['error'] = 'Some fee-query tasks failed: {}'.format(','.join(failed_tasks))

    return reply


def check_operations( fqu, operations, owner_privkey_info, payment_privkey_info, required_checks=[], transfer_address=None, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that an operation sequence can be performed, given the set of sanity checks that must pass.
    Return {'status': True, 'opchecks': {...}} if so
    Return {'error': ...} if not.
    """
    
    assert len(required_checks) > 0, "Missing required checks"

    log.debug("Check {} on {}: test {}".format(', '.join(operations), fqu, ', '.join(required_checks)))

    owner_address = get_privkey_info_address(owner_privkey_info)
    payment_address = get_privkey_info_address(payment_privkey_info)

    sg = ScatterGather()

    res = operation_sanity_checks(fqu, operations, sg, payment_privkey_info, owner_privkey_info,
                                  required_checks=required_checks,
                                  min_confirmations=min_payment_confs, config_path=config_path,
                                  transfer_address=transfer_address, proxy=proxy )

    if 'error' in res:
        log.error("Failed to begin operation sanity checks: {}".format(res['error']))
        return {'error': 'Failed to perform sanity checks'}

    sg.run_tasks()

    opchecks = interpret_operation_sanity_checks( fqu, operations, sg )
    if 'error' in opchecks:
        log.error("Failed to interpret operation sanity checks")
        return {'error': 'Failed operation sanity checks:\n{}'.format(opchecks['error']), 'opchecks': opchecks}

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
                'opchecks': opchecks}

    balance = sg.get_result('get_balance')['status']

    if balance < opchecks['total_estimated_cost']:
        msg = 'Address {} does not have enough balance (need {}, have {}).'
        msg = msg.format(payment_address, opchecks['total_estimated_cost'], balance)
        return {'error': msg, 'opchecks': opchecks}

    # checks pass!
    return {'status': True, 'opchecks': opchecks}


def _check_op(fqu, operation, required_checks, owner_privkey_info, payment_privkey_info, transfer_address=None, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Check an operation
    Return {'status': True, 'opchecks': {...}, 'tx_fee': ...} on success
    Return {'error': ...} on error
    """
    # find tx fee, and do sanity checks
    assert owner_privkey_info
    assert payment_privkey_info

    res = check_operations( fqu, [operation], owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs,
                            transfer_address=transfer_address, required_checks=required_checks, config_path=config_path, proxy=proxy )

    opchecks = res.get('opchecks', None)
    tx_fee = None

    if opchecks:
        tx_fee = opchecks.get('total_tx_fees', None)

    if 'error' in res:
        return {'error': res['error'], 'tx_fee': tx_fee, 'opchecks': opchecks}

    else:
        return {'status': True, 'tx_fee': tx_fee, 'opchecks': opchecks}


def check_preorder(fqu, cost_satoshis, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a preorder can go through.

    Return {'status': True, 'opchecks': {...}, 'tx_fee': ...}
    """

    # find tx fee, and do sanity checks
    assert owner_privkey_info
    assert payment_privkey_info

    required_checks = ['is_name_available', 'is_payment_address_usable']

    res = check_operations( fqu, ['preorder'], owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs,
                            required_checks=required_checks, config_path=config_path, proxy=proxy )

    opchecks = res.get('opchecks', None)
    tx_fee = None

    if opchecks:
        tx_fee = opchecks.get('total_tx_fees', None)

    if 'error' in res:
        return {'error': res['error'], 'opchecks': res.get('opchecks', None), 'tx_fee': res.get('opchecks', {}).get('total_tx_fees', None)}

    if cost_satoshis is not None:
        if opchecks['name_price'] > cost_satoshis:
            return {'error': 'Invalid cost: expected {}, got {}'.format(opchecks['name_price'], cost_satoshis), 'tx_fee': tx_fee, 'opchecks': opchecks}

    return {'status': True, 'tx_fee': tx_fee, 'opchecks': opchecks}


def check_register(fqu, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a register can go through
    """
    required_checks = ['is_name_available', 'owner_can_receive', 'is_payment_address_usable']
    return _check_op(fqu, 'register', required_checks, owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy )


def check_update(fqu, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that an update can go through
    """
    required_checks = ['is_name_registered', 'is_owner_address_usable', 'is_payment_address_usable', 'is_name_owner']
    return _check_op(fqu, 'update', required_checks, owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy)


def check_transfer(fqu, transfer_address, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a transfer can go through
    """
    required_checks = ['is_name_registered', 'is_owner_address_usable', 'is_payment_address_usable', 'is_name_owner', 'recipient_can_receive']
    return _check_op(fqu, 'transfer', required_checks, owner_privkey_info, payment_privkey_info, transfer_address=transfer_address, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy)


def check_renewal(fqu, renewal_fee, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a renew can go through
    """ 
    # find tx fee, and do sanity checks
    assert owner_privkey_info
    assert payment_privkey_info

    required_checks = ['is_name_registered', 'is_name_owner', 'is_owner_address_usable', 'is_payment_address_usable']
    res = check_operations( fqu, ['renewal'], owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs,
                            required_checks=required_checks, config_path=config_path, proxy=proxy )

    opchecks = res.get('opchecks', None)
    tx_fee = None

    if opchecks:
        tx_fee = opchecks.get('total_tx_fees', None)

    if 'error' in res:
        return {'error': res['error'], 'opchecks': res.get('opchecks', None), 'tx_fee': res.get('opchecks', {}).get('total_tx_fees', None)}

    if renewal_fee is not None:
        if opchecks['name_price'] > renewal_fee:
            return {'error': 'Invalid cost: expected {}, got {}'.format(opchecks['name_price'], renewal_fee), 'tx_fee': tx_fee, 'opchecks': opchecks}

    return {'status': True, 'tx_fee': tx_fee, 'opchecks': opchecks}


def check_revoke(fqu, owner_privkey_info, payment_privkey_info, min_payment_confs=TX_MIN_CONFIRMATIONS, config_path=CONFIG_PATH, proxy=None ):
    """
    Verify that a revoke can go through
    """
    required_checks = ['is_name_registered', 'is_name_owner', 'is_owner_address_usable', 'is_payment_address_usable']
    return _check_op(fqu, 'revoke', required_checks, owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs, config_path=config_path, proxy=proxy )

