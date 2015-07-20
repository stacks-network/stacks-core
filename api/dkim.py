# -*- coding: utf-8 -*-
"""
    Get DKIM info from DNS
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import socket
import dns.resolver

DNS_SERVERS = ['8.8.8.8', '8.8.4.4']  # use a Google DNS servers as default
DKIM_RECORD_PREFIX = 'google._domainkey.'
ADDITIONAL_RDCLASS = 65535

# ----------------------------------------


def dns_resolver(domain):

    import dns.name
    import dns.message
    import dns.query
    import dns.flags

    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    request = dns.message.make_query(domain, dns.rdatatype.TXT)
    request.flags |= dns.flags.AD
    request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                       dns.rdatatype.OPT, create=True, force_unique=True)

    data = dns.query.udp(request, DNS_SERVERS[0])
    return data.to_text()


def parse_pubkey_from_data(data):

    public_key = None

    data = data.split('\n')

    for entry in data:
        if "DKIM" in entry:
            data = entry.split(' ')

            for entry in data:
                if "p=" in entry:
                    public_key = entry.split("p=")[1]
                    public_key = public_key[:-1]

    return public_key


# -----------------------------------
if __name__ == '__main__':

    test_domain = DKIM_RECORD_PREFIX + 'onename.com'
    dns_data = dns_resolver(test_domain)
    public_key = parse_pubkey_from_data(dns_data)

    print public_key
