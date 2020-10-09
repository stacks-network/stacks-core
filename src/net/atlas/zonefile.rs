

enum Record {
    A,      // Host address
    NS,     // Authoritative name server
    MD,     // Mail destination (Obsolete - use MX)
    MF,     // Mail forwarder (Obsolete - use MX)
    CNAME,  // Canonical name for an alias
    SOA,    // Marks the start of a zone of authority
    MB,     // Mailbox domain name (EXPERIMENTAL)
    MG,     // Mail group member (EXPERIMENTAL)
    MR,     // Mail rename domain name (EXPERIMENTAL)
    NULL,   // Null RR (EXPERIMENTAL)
    WKS,    // Well known service description
    PTR,    // Domain name pointer
    HINFO,  // Host information
    MINFO,  // Mailbox or mail list information
    MX,     // Mail exchange
    TXT,    // Text strings
}

impl Record {
    fn parse() -> Option<Record> {
        None
    }
}

struct Zonefile {
    origin: String,
    ttl: u16,
    records: Vec<Record>,
}

impl Zonefile {
    fn parse() -> Option<Zonefile> {
        None
    }
}