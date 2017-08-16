#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2017 by Blockstack.org

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

import os, tempfile, sys, time, re
import json, logging
import sqlite3
import threading
import BaseHTTPServer, requests
import jsonschema

from blockstack_client import schemas, subdomains
from blockstack_client import constants as blockstack_constants
import blockstack_zones

from subdomain_registrar import config, util

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
fh = logging.FileHandler(config.get_logfile())
fh.setLevel(logging.DEBUG)
log.addHandler(fh)

class SubdomainOpsQueue(object):
    def __init__(self, domain, db_path):
        dirname = os.path.dirname(db_path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        self.entries_per_tx_hint = 24
        self.zonefile_limit = 4096
        self.domain = domain
        self.conn = sqlite3.connect(db_path)
        self.queue_table = "queue_{}".format(domain.replace('.', '_'))
        self._create_if_needed()

    def _create_if_needed(self):
        queue = """CREATE TABLE {} (
        received_at INTEGER PRIMARY KEY,
        subdomain TEXT NOT NULL,
        subdomain_name TEXT NOT NULL,
        in_tx TEXT);
        """.format(self.queue_table)

        index = "CREATE INDEX subdomain_{} ON {} (subdomain)".format(
            self.queue_table, self.queue_table)

        check = """SELECT name FROM sqlite_master WHERE
         type='table' AND name='{}';""".format(self.queue_table)

        c = self.conn.cursor()
        r_val = self._execute(check, ()).fetchall()
        if len(r_val) > 0:
            return
        c.execute(queue)
        c.execute(index)
        self.conn.commit()

    def _execute(self, sql, args):
        c = self.conn.cursor()
        r_val = c.execute(sql, args)
        self.conn.commit()
        return r_val

    def _add_subdomain_row(self, jsoned_strings, subdomain_name):
        sql = """INSERT INTO {} (subdomain, subdomain_name)
                 SELECT ?, ?
                 WHERE NOT EXISTS ( SELECT 1 FROM {} WHERE subdomain_name = ? )""".format(
                     self.queue_table, self.queue_table)
        inserted = self._execute(sql, (jsoned_strings, subdomain_name, subdomain_name)).rowcount
        if inserted <= 0:
            raise subdomains.SubdomainAlreadyExists(subdomain_name, self.domain)

    def _get_queued_rows(self):
        sql = """SELECT received_at, subdomain FROM {}
        WHERE in_tx ISNULL ORDER BY received_at ASC LIMIT {};
        """.format(self.queue_table, self.entries_per_tx_hint)
        out = list(self._execute(sql, ()).fetchall())
        return [ (received_at,
                  subdomains.Subdomain.parse_subdomain_record(self.domain, json.loads(packed_subdomain)))
                 for received_at, packed_subdomain in out ]

    def _set_in_tx(self, subds, txid):
        sql = """UPDATE {} SET in_tx = ?
        WHERE received_at IN ({})""".format(
            self.queue_table,
            ",".join("?" * len(subds)))
        self._execute(sql, [txid] + list(subds))

    def get_subdomain_status(self, subdomain):
        sql = """SELECT in_tx FROM {} WHERE subdomain_name = ?""".format(
            self.queue_table)
        out = self._execute(sql, (subdomain,))
        try:
            status = out.fetchone()[0]
        except Exception as e:
            log.warn("Subdomain {} not found in registrar".format(subdomain))
            return None
        if not status:
            return {"status" : "Subdomain is queued for update and should be announced within the next few blocks."}
        if status.startswith("ERR"):
            return {"error" :
                    "There was a problem propagating your subdomain registration. The" +
                    " server experience an {} error while trying to issue the update.".format(status)}
        return {"status" :
                ("Your subdomain was registered in transaction {} -- it should propagate" +
                 " on the network once it has 6 confirmations.").format(status)}

    def add_subdomain_to_queue(self, subdomain):
        name = subdomain.subdomain_name
        packed_dict = subdomain.as_zonefile_entry()
        jsoned = json.dumps(packed_dict)
        self._add_subdomain_row(jsoned, name)

    def submit_transaction(self):
        queued_rows = list(self._get_queued_rows())
        if len(queued_rows) == 0:
            return {'status' : 'true',
                    'subdomain_updates' : 0}

        zf_init = get_zonefile(self.domain)
        for slice_sz in range(len(queued_rows), -1, -1):
            if slice_sz == 0:
                return {'error' :
                        "Failed to construct small enough zonefile (size < {})".format(self.zonefile_limit)}
            cur_queued_rows = queued_rows[:slice_sz]
            indexes, entries = zip(* cur_queued_rows)

            to_add = list(entries)

            kwargs = {}
            zf_txt, subs_failed = util.add_subdomains(to_add, self.domain, zf_init)

            if len(subs_failed) > 0:
                indexes = list(indexes)
                db_indexes_failed = []
                subs_failed.sort(reverse=True)
                for i in subs_failed:
                    db_indexes_failed.append(indexes.pop(i))
                    log.info("Subdomain already existed for ({})".format(
                        [ entries[i].name for i in subs_failed ] ))
                    self._set_in_tx(db_indexes_failed, "ERR:ALREADYEXISTED")
                if len(indexes) == 0:
                    return {'status' : 'true',
                            'subdomain_updates' : 0}

            if len(zf_txt) < self.zonefile_limit:
                break

        # issue user zonefile update to API endpoint

        target = "/v1/names/{}/zonefile".format(self.domain)
        resp = rest_to_api(target, data = json.dumps({'zonefile' : zf_txt}), call = requests.put)

        log.info("Submitting zonefile (length = {})".format(len(zf_txt)))

        if resp.status_code != 202:
            msg = 'Error submitting subdomain bundle: {}'.format(resp.text)
            log.error(msg)
            try:
                resp_js = resp.json()
                if "maxLength" in str(resp_js["error"]):
                    self.zonefile_limit = len(zf_txt) - 1
                    log.warn("Zonefile too large for server, reducing zonefile size to {}".format(
                        self.zonefile_limit))
                    return {'error' : 'Zonefile too large, try again.', 'retry' : True}
            except Exception as e:
                pass

            self._set_in_tx(indexes, "ERR:{}".format(msg))
            return {'error' : msg}

        try:
            resp_js = resp.json()
        except Exception as e:
            log.error("Error in response: {}".format(resp))
            log.exception(e)
            return {'error' : 'Error in parsing response'}

        if 'error' in resp_js:
            msg = 'Error submitting subdomain bundle: {}'.format(resp_js['error'])
            log.error(msg)
            self._set_in_tx(indexes, "ERR:{}".format(msg))
            return {'error' : msg}

        txid = str(resp_js['transaction_hash'])
        self._set_in_tx(indexes, txid)

        self.entries_per_tx_hint = min(len(indexes) + 1, config.max_entries_per_zonefile())

        log.info('Issued update for {} subdomain entries. In tx: {}'.format(
            len(indexes), txid))
        return {'status' : 'true',
                'subdomain_updates' : len(indexes),
                'transaction_hash' : txid}

def get_queued_name(subdomain, domain_name):
    if does_subdomain_exist(subdomain, domain_name):
        return {'status' : 'Subdomain already propagated'}
    q =  SubdomainOpsQueue(domain_name, config.get_subdomain_registrar_db_path())
    status = q.get_subdomain_status(subdomain)
    if status:
        return status
    return {'error' : 'Subdomain not registered with this registrar', 'status_code' : 404}

def queue_name_for_registration(subdomain, domain_name):
    if does_subdomain_exist(subdomain.subdomain_name, domain_name):
        raise subdomains.SubdomainAlreadyExists(subdomain.subdomain_name, domain_name)
    q =  SubdomainOpsQueue(domain_name, config.get_subdomain_registrar_db_path())
    q.add_subdomain_to_queue(subdomain)
    return {'status' : 'true',
            'message' : 'Subdomain registration queued.'}

def parse_subdomain_request(domain_name, input_str):
    schema = {
        'type' : 'object',
        'properties' : {
            'name' : {
                'type': 'string',
                'pattern': config.SUBDOMAIN_NAME_PATTERN
            },
            'owner_address' : {
                'type': 'string',
                'pattern': schemas.OP_ADDRESS_PATTERN
            },
            'zonefile' : {
                'type' : 'string',
                'maxLength' : blockstack_constants.RPC_MAX_ZONEFILE_LEN
            }
        },
        'required':[
            'name', 'owner_address', 'zonefile'
        ],
        'additionalProperties' : True
    }
    request = json.loads(input_str)
    jsonschema.validate(request, schema)

    zonefile_str = str(request['zonefile'])
    if zonefile_str is None:
        raise Exception("Request lacked either a zonefile_str or an uris entry")

    owner_entry = str(request['owner_address'])

    return subdomains.Subdomain(
        domain_name,
        request['name'], owner_entry,
        n=0, zonefile_str = zonefile_str)

def run_registrar(domain_name):
    """
    Set singleton state and start the registrar thread.
    Return the registrar state on success
    Return None on error
    """
    lockfile = config.get_lockfile()

    # if we're already running, then bail
    if SubdomainLock.is_lockfile_valid(lockfile):
        log.debug("SubdomainRegistrarWorker already initialized")
        return None

    try:
        SubdomainLock.acquire(lockfile)
    except (IOError, OSError):
        try:
            os.unlink(lockfile)
        except:
            pass

        log.debug("Extra worker exiting (failed to lock)")
        return

    log.info("Initialize Subdomain Registrar State from %s" % (lockfile))

    registrar_thread = SubdomainRegistrarWorker(domain_name)
    registrar_thread.start()

    api_thread = SubdomainRegistrarRPCWorker(domain_name)
    api_thread.start()

    while True:
        try:
            time.sleep(60)
        except (KeyboardInterrupt, Exception) as e:
            return handle_interrupt(api_thread, registrar_thread)

def handle_interrupt(api_thread, registrar_thread):
    try:
        log.info("Interrupt received, beginning shutdown.")
        api_thread.request_stop()
        api_thread.join()
        registrar_thread.request_stop()
        registrar_thread.join()
        log.info("Registrar threads shutdown")
        return
    except (KeyboardInterrupt, Exception) as e:
        return handle_interrupt(api_thread, registrar_thread)

class SubdomainRegistrarWorker(threading.Thread):
    def __init__(self, domain_name):
        super(SubdomainRegistrarWorker, self).__init__()
        self.domain_name = domain_name
        db_path = config.get_subdomain_registrar_db_path()
        self.queue_opts = (domain_name, db_path)
        self.running = True
        self.tx_every = config.get_tx_frequency()
    def request_stop(self):
        self.running = False
    def run(self):
        queue = SubdomainOpsQueue(*self.queue_opts)
        while self.running:
            # todo: wake up more frequently, poll blocks,
            #        track last block with tx, and do tx_every in
            #        block time, rather than clock time.

            for i in range(5): # number of retries
                try:
                    result = queue.submit_transaction()
                except Exception as e:
                    log.error("Error trying to submit transaction")
                    log.exception(e)
                    break
                if not ('error' in result and result.get('retry', False)):
                    break

            for i in xrange(0, int(self.tx_every)):
                try:
                    time.sleep(1)
                except:
                    log.debug("Subdomain's sleep interrupted")
                if not self.running:
                    return

class SubdomainRegistrarRPCWorker(threading.Thread):
    def __init__(self, domain_name):
        super(SubdomainRegistrarRPCWorker, self).__init__()
        bind_address = config.get_api_bind_address()
        bind_port = config.get_api_bind_port()
        self.server = BaseHTTPServer.HTTPServer(
            (bind_address, bind_port), SubdomainRegistrarRPCHandler)
        self.server.domain_name = domain_name
    def request_stop(self):
        self.server.shutdown()
    def run(self):
        self.server.serve_forever()

class SubdomainRegistrarRPCHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def send_message(self, code, message):
        self.send_response(code)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(message + "\r\n")

    def do_OPTIONS(self):
        """
        Give back CORS preflight check headers
        """
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')    # CORS
        self.send_header('Access-Control-Allow-Methods', 'GET, POST')
        self.send_header('Access-Control-Allow-Headers', 'content-type, authorization, range')
        self.send_header('Access-Control-Expose-Headers', 'content-length')
        self.send_header('Access-Control-Max-Age', 21600)
        self.end_headers()
        return


    def do_GET(self):
        path = self.path
        if path[-1] == "/":
            path = path[:-1]
        if not str(path).startswith("/status/"):
            return self.send_message(404, json.dumps({"error" : "Unsupported API method"}))
        name = path[len("/status/"):]
        if re.match(config.SUBDOMAIN_NAME_PATTERN, name) is None:
            return self.send_message(404, json.dumps({"error" : "Invalid subdomain supplied"}))
        status = get_queued_name(name, self.server.domain_name)
        if "error" in status:
            status_code = status.get("status_code", 500)
            return self.send_message(status_code, json.dumps({"error": status["error"]}))
        return self.send_message(200, json.dumps(status))

    def do_POST(self):
        path = self.path
        if path[-1] == "/":
            path = path[:-1]
        if str(path) != "/register":
            return self.send_message(404, json.dumps({"error" : "Unsupported API method"}))
        length = int(self.headers.getheader('content-length'))
        if length > 1024 * 1024:
            return self.send_message(403, json.dumps({"error" : "Content length too long. Request Denied."}))
        try:
            subdomain = parse_subdomain_request(self.server.domain_name, self.rfile.read(length))
        except Exception as e:
            log.exception(e)
            return self.send_message(401, json.dumps({"error" : "Problem parsing request"}))

        try:
            queued_resp = queue_name_for_registration(subdomain, self.server.domain_name)
        except subdomains.SubdomainAlreadyExists as e:
            log.exception(e)
            return self.send_message(403, json.dumps({"error" : "Subdomain already exists on this domain"}))

        if "error" in queued_resp:
            return self.send_message(500, json.dumps(queued_resp))
        return self.send_message(202, json.dumps(queued_resp))

class SubdomainLock(object):
    @staticmethod
    def is_lockfile_stale(path):
        with open(path, "r") as f:
            dat = f.read()
            try:
                pid = int(dat.strip())
            except:
                # corrupt
                pid = -1
        return pid != os.getpid()
    @staticmethod
    def lockfile_write( fd ):
        buf = "%s\n" % os.getpid()
        nw = 0
        while nw < len(buf):
            try:
                rc = os.write( fd, buf[nw:] )
                nw += rc
            except:
                log.error("Failed to write lockfile")
                return False
        return True
    @staticmethod
    def acquire( lockfile_path ):
        dirname = os.path.dirname(lockfile_path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        fd, path = tempfile.mkstemp(prefix=".subd.registrar.lock.", dir=dirname)
        os.link( path, lockfile_path )
        try:
            os.unlink(path)
        except:
            pass

        # success!  write the lockfile
        rc = SubdomainLock.lockfile_write( fd )
        os.close( fd )

        if not rc:
            log.error("Failed to write lockfile")
            raise IOError("Failed to write lockfile")

    @staticmethod
    def is_lockfile_valid( lockfile_path ):
        """
        Does the lockfile exist and does it correspond
        to a running registrar?
        """
        if os.path.exists(lockfile_path):
            # is it stale?
            if SubdomainLock.is_lockfile_stale( lockfile_path ):
                log.debug("Removing stale subdomain lockfile")
                os.unlink(lockfile_path)
                return False
            else:
                # not stale
                return True
        else:
            return False

def get_zonefile(domain):
    resp = rest_to_api("/v1/names/{}/zonefile".format(domain))
    if resp.status_code != 200:
        log.error("Error fetch zonefile for {} : {} {}".format(
            domain, resp.status_code, resp.text))
        raise Exception("Failed to fetch zonefile")
    zf_raw = resp.json()["zonefile"]
    if zf_raw:
        return blockstack_zones.parse_zone_file(str(zf_raw))
    raise Exception("No zonefile returned")

def does_subdomain_exist(subdomain, domain):
    resp = rest_to_api("/v1/users/{}.{}/".format(subdomain, domain))
    return (resp.status_code == 200)

def rest_to_api(target, data=None, call = requests.get):
    api_endpoint, authentication = config.get_core_api_endpoint()
    headers = {}
    headers['authorization'] = 'bearer {}'.format(authentication)
    headers['origin'] = 'http://localhost:3000' # lies.
    headers['content-type'] = 'application/json'
    target = api_endpoint + target

    if data is None:
        return call(target, headers = headers)
    else:
        return call(target, headers = headers,
                    data = data)

START_HELP = """ usage: blockstack-subdomain-registrar start <domainname:required> """
def main_entry():
    if len(sys.argv) < 2:
        print START_HELP
        exit(1)
    command = sys.argv.pop(1)
    if command == "start":
        if len(sys.argv) < 2:
            print START_HELP
            exit(1)
        domain_name = sys.argv[1]
        run_registrar(domain_name)

if __name__ == "__main__":
    main_entry()
