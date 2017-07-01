
class SubdomainOpsQueue(object):
    def __init__(self, domain, db_path):
        self.domain = domain
        self.conn = sqlite3.connect(db_path)
        self.queue_table = "queue_{}".format(domain.replace('.', '_'))

    def _create_if_needed(self):
        queue = """CREATE TABLE {} (
        received_at INTEGER PRIMARY KEY,
        subdomain TEXT PRIMARY KEY,
        in_tx TEXT,
        signature TEXT);
        """.format(self.queue_table)

        index = "CREATE INDEX subdomain ON {} (subdomain)".format(
            self.queue_table)

