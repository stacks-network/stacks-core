#!/usr/bin/env python2
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

import json
import sys
import os
import urllib2
import hashlib
import threading
import traceback
import gc
import signal
import time

from .config import get_config
from .logger import get_logger

log = get_logger('blockstack-client')

def exit_with_error(error_message, help_message=None):

    result = {'error': error_message}

    if help_message is not None:
        result['help'] = help_message
    friendly_newlines = sys.stderr.isatty()
    print_result(result, friendly_newlines=friendly_newlines, file=sys.stderr)
    sys.exit(0)


def pretty_dump(data):
    """ format data
    """

    if type(data) is list:

        if len(data) == 0:
            # we got an empty array
            data = {}
        else:
            # Netstring server responds with [{data}]
            log.debug("converting [] to {}")
            data = data[0]

    if type(data) is not dict:
        try:
            data = json.loads(data)
        except Exception as e:
            # data is not valid json, convert to json
            data = {'result': data}

    return json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))


def pretty_print(data):

    try:
        data = data[0]
    except:
        pass

    if type(data) is not dict:
        try:
            data = json.loads(data)
        except Exception as e:
            log.debug("ERROR in pretty print: %s" % e)

    print pretty_dump(data)


def print_result(json_str, friendly_newlines = False, file=sys.stdout):
    data = pretty_dump(json_str)

    if friendly_newlines:
        # note: this makes the produced output INVALID json.
        #       which is why it only does this on error exits.
        data = data.replace("\\n", "\n")

    if data != "{}":
        print >> file, data


def satoshis_to_btc(satoshis):

    return satoshis * 0.00000001


def btc_to_satoshis(btc):

    return int(btc / 0.00000001)


def daemonize( logpath, child_wait=None ):
    """
    Double-fork and make a daemon.
    Have the intermediate child call child_wait()
    to block its exit until the child is "ready"
    (i.e. child_wait() returns)

    Return 0 if we're the daemon child
    Return >0 if we're the parent
    """
    logfile = open(logpath, 'a+')
    
    # turn off GC across the fork
    gc.collect(2)
    gc.collect(1)
    gc.collect(0)
    gc.disable()
    
    child_pid = os.fork()

    if child_pid == 0:
        # child!
        sys.stdin.close()
        os.dup2(logfile.fileno(), sys.stdout.fileno())
        os.dup2(logfile.fileno(), sys.stderr.fileno())

        # we don't have many other fds open yet
        for i in xrange(3, 1024):
            if i == logfile.fileno():
                continue

            try:
                os.close(i)
            except:
                pass

        os.setsid()

        daemon_pid = os.fork()
        if daemon_pid == 0:
            # daemon! chdir and return
            os.chdir('/')
            gc.enable()
            gc.collect(2)
            gc.collect(1)
            gc.collect(0)
            return 0

        elif daemon_pid > 0:
            # parent (intermediate child)
            # wait for child to fully initialize...
            res = True
            if child_wait is not None:
                res = child_wait()

            if res:
                sys.exit(0)
            else:
                sys.exit(1)

        else:
            # error
            sys.exit(1)

    elif child_pid > 0:
        # grand-parent (caller)
        # re-activate gc
        gc.enable()
        gc.collect(2)
        gc.collect(1)
        gc.collect(0)

        # wait for intermediate child.
        # panic if we don't hear back after 1 minute
        timeout = 60
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            # wait around so we can attach gdb or whatever
            timeout = 60000

        for i in xrange(0, timeout):
            pid, status = os.waitpid(child_pid, os.WNOHANG)
            if pid == 0:
                # still waiting
                time.sleep(1)
                log.debug("Still waiting on {}".format(child_pid))
                continue

            # child has exited!
            if os.WEXITSTATUS(status) == 0:
                return child_pid
            else:
                log.error("Child exit status {}".format(status))
                return -1

        # child has not exited yet.  This is not okay.
        log.error("Child PID={} did not exit.  Killing it instead and failing...".format(child_pid))
        os.kill(child_pid, signal.SIGKILL)
        return -1
    
    else:
        # failed to fork 
        log.error("Failed to fork")
        return -1

    return 0


def url_to_host_port(url, port=None):
    """
    Given a URL, turn it into (host, port).
    Return (None, None) on invalid URL
    """
    if not url.startswith('http://') or not url.startswith('https://'):
        url = 'http://' + url

    if not port:
        conf = get_config()
        port = conf['port']

    urlinfo = urllib2.urlparse.urlparse(url)
    hostport = urlinfo.netloc

    parts = hostport.split('@')
    if len(parts) > 2:
        return None, None

    if len(parts) == 2:
        hostport = parts[1]

    parts = hostport.split(':')
    if len(parts) > 2:
        return None, None

    if len(parts) == 2:
        try:
            port = int(parts[1])
            assert 0 < port < 65535, 'Invalid port'
        except TypeError:
            return None, None

    return parts[0], port


def atlas_inventory_to_string( inv ):
    """
    Inventory to string (bitwise big-endian)
    """
    ret = ""
    for i in xrange(0, len(inv)):
        for j in xrange(0, 8):
            bit_index = 1 << (7 - j)
            val = (ord(inv[i]) & bit_index)
            if val != 0:
                ret += "1"
            else:
                ret += "0"

    return ret


def streq_constant(s1, s2):
    """
    constant-time string comparison.
    Return True if equal
    Return False if not equal
    """
    res = 0
    s1h = hashlib.sha256(s1).digest()
    s2h = hashlib.sha256(s2).digest()
    for s1c, s2c in zip(s1h, s2h):
        # will xor to 0 for each char if equal
        res |= ord(s1c) ^ ord(s2c)

    return res == 0


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
                log.debug("Start task (single-threaded) '{}'".format(task_name))
                res = ScatterGatherThread.do_work(task_call)
                log.debug("Join task (single-threaded) '{}'".format(task_name))
                self.results[task_name] = res

        self.ran = True
        return self.results

