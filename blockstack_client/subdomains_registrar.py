import os, tempfile
import json
import sqlite3
import thread

global __registrar_state

class SubdomainOpsQueue(object):
    def __init__(self, domain, db_path, entries_per_tx = 100):
        self.domain = domain
        self.conn = sqlite3.connect(db_path)
        self.queue_table = "queue_{}".format(domain.replace('.', '_'))
        self._create_if_needed()
        self.entries_per_tx = entries_per_tx
#        self.watch_tx_table = "txwatch_{}".format(domain.replace('.', '_'))

    def _create_if_needed(self):
        queue = """CREATE TABLE {} (
        received_at INTEGER PRIMARY KEY,
        subdomain TEXT NOT NULL,
        in_tx TEXT);
        """.format(self.queue_table)

        index = "CREATE INDEX subdomain ON {} (subdomain)".format(
            self.queue_table)

        c = self.conn.cursor()
        c.execute(queue)
        c.execute(index)
        self.conn.commit()
    def _exececute(self, sql, args):
        c = self.conn.cursor()
        r_val = c.execute(sql, args)
        self.conn.commit()
        return r_val

    def _add_subdomain_row(self, jsoned_strings):
        sql = "INSERT INTO {} VALUES (?)".format(self.queue)
        self._execute(sql, (jsoned_strings,))

    def _get_queued_rows(self):
        sql = """SELECT subdomain FROM {} 
        WHERE in_tx ISNULL
        LIMIT {} ORDER BY received_at ASC;
        """.format(self.queue)
        return self._execute(sql, (,))

    def _set_in_tx(self, subdomains, txid):
        sql = """UPDATE {} SET in_tx = ?
        WHERE subdomain IN ({})""".format(
            self.queue_table,
            ",".join("?" * len(subdomains)))
        self._execute(sql, subdomains)

    def add_subdomain_to_queue(self, subdomain):
        packed_strings = subdomain.pack_subdomain()
        jsoned_strings = json.dumps(packed_strings)
        self._add_subdomain_row(jsoned_strings)

    def submit_transaction(self):
        entries = self._get_queued_rows()
        if len(entries) == 0:
            return {'status' : 'true',
                    'subdomain_updates' : 0}
        tx_resp = subdomains.add_subdomains(entries, self.domain)
        if 'error' in tx_resp:
            log.error('Error submitting subdomain bundle: {}'.format(tx_resp['error']))
            return tx_resp
        self._set_in_tx(entries, tx_resp['transaction_hash'])
        return {'status' : 'true',
                'subdomain_updates' : len(entries),
                'transaction_hash' : tx_resp['transaction_hash']}


def set_registrar_state(config_path=CONFIG_PATH):
    """
    Set singleton state and start the registrar thread.
    Return the registrar state on success
    Return None on error
    """
    global __registrar_state
    assert config_path is not None

    # if we're already running, then bail
    if SubdomainLock.is_lockfile_valid( config_path ):
        log.debug("SubdomainRegistrarWorker already initialized")
        return None

    try:
        SubdomainLock.acquire( config_path )
    except (IOError, OSError):
        try:
            os.unlink(path)
        except:
            pass

        log.debug("Extra worker exiting (failed to lock)")
        return

    log.info("Initialize Subdomain Registrar State from %s" % (config_path))

    __registrar_state = SubdomainRegistrarWorker(config_path)
    __registrar_state.start()

    return __registrar_state

def registrar_shutdown(config_path=CONFIG_PATH):
    """
    Shut down existing state
    """
    global __registrar_state
    if __registrar_state is None:
        return

    log.info("Shut down Subdomains Registrar State")
    __registrar_state.request_stop()
    __registrar_state.join()
    __registrar_state = None

def queue_name_for_registration(subdomain, domain_name, config_path=CONFIG_PATH):
    # check if we manage this subdomain.
    domains = config.get_domains_managed()
    if domain not in domains:
        log.error("Domain {} not managed by this node. We manage these: {}".format(
            domain, domains))
        raise Exception("The domain {} is not managed by this node.".format(domain))
    q =  SubdomainOpsQueue(domain_name, config.get_subdomain_registrar_db_path(config_path))
    q.add_subdomain_to_queue(subdomain)
    return {'status' : 'true',
            'message' : 'Subdomain registration queued.'}

class SubdomainRegistrarWorker(threading.Thread):
    def __init__(self, domain_name, config_path=CONFIG_PATH):
        self.domain_name = domain_name
        db_path = config.get_subdomain_registrar_db_path(config_path)
        tx_every = config.get_subdomain_registrar_poll_freq(config_path)
        self.queue = SubdomainOpsQueue(domain_name, db_path)
        self.running = True
        self.tx_every = 15 * 60
    def request_stop(self):
        self.running = False
    def run(self):
        while self.running:
            # todo: wake up more frequently, poll blocks,
            #        track last block with tx, and do tx_every in
            #        block time, rather than clock time.
            self.queue.submit_transaction()

            for i in xrange(0, int(tx_every)):
                try:
                    time.sleep(1)
                except:
                    log.debug("Subdomain's sleep interrupted")
                if not self.running:
                    return

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
    def get_lockfile_path( config_path, domain_name ):
        fname = "subdomain_registrar.{}.lock".format(domain_name)
        return os.path.join( os.path.dirname(config_path), fname )
    @staticmethod
    def acquire( config_path ):
        fd, path = tempfile.mkstemp(prefix=".subd.registrar.lock.",
                                    dir=os.path.dirname(config_path))
        os.link( path, SubdomainLock.get_lockfile_path (config_path) )
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
    def is_lockfile_valid( config_path ):
        """
        Does the lockfile exist and does it correspond
        to a running registrar?
        """
        lockfile_path = SubdomainLock.get_lockfile_path( config_path )
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
