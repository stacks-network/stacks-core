import json
import sqlite3

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

#        txwatch = """CREATE TABLE {} (
#        tx TEXT PRIMARY KEY,
#        confs INTEGER);
#        """.format(self.watch_tx_table)

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
        tx_resp = subdomains.add_subdomains(entries, self.domain)
        if 'error' in tx_resp:
            log.error('Error submitting subdomain bundle: {}'.format(tx_resp['error']))
            return tx_resp
        self._set_in_tx(entries, tx_resp['transaction_hash'])
        return {'status' : 'true',
                'subdomain_updates' : len(entries),
                'transaction_hash' : tx_resp['transaction_hash']}


def set_registrar_state(config_path=None, wallet_keys=None):
    """
    Set singleton state and start the registrar thread.
    Return the registrar state on success
    Return None on error
    """
    global __registrar_state
    assert config_path is not None

    # if we're already running, then bail
    if RegistrarWorker.is_lockfile_valid( config_path ):
        log.debug("SubdomainRegistrarWorker already initialized")
        return None

    log.info("Initialize Subdomain Registrar State from %s" % (config_path))
    __registrar_state = RegistrarWorker(config_path)

    __registrar_state.start()
    return __registrar_state

def registrar_shutdown(config_path=None):
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

class SubdomainRegistrarWorker(object):
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
    def is_lockfile_valid( cls, config_path ):
        """
        Does the lockfile exist and does it correspond
        to a running registrar?
        """
        lockfile_path = cls.get_lockfile_path( config_path )
        if os.path.exists(lockfile_path):
            # is it stale?
            if cls.is_lockfile_stale( lockfile_path ):
                return False

            else:
                # not stale
                return True

        else:
            return False
