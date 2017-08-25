#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack Core
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack Core.

    Blockstack Core is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack Core is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack Core. If not, see <http://www.gnu.org/licenses/>.
"""

import socket
import dns.resolver

DNS_SERVERS = ['8.8.8.8', '8.8.4.4']  # use a Google DNS servers as default
DKIM_RECORD_PREFIX = 'blockchainid._domainkey.'
ADDITIONAL_RDCLASS = 65535


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
    public_key = key_type = key_curve = None

    data = data.split('\n')
    for entry in data:
        if "DKIM" in entry:
            data = entry.split(' ')

            for entry in data:
                if "p=" in entry:
                    public_key = entry.split("p=")[1]
                    public_key = public_key[:-1]
                if "k=" in entry:
                    key_type = entry.split("k=")[1]
                    key_type = key_type[:-1]
                if "n=" in entry:
                    key_curve = entry.split("n=")[1]
                    key_curve = key_curve[:-1]

    return {
        'public_key': public_key,
        'key_type': key_type,
        'key_curve': key_curve
    }


if __name__ == '__main__':
    test_domain = DKIM_RECORD_PREFIX + 'onename.com'
    dns_data = dns_resolver(test_domain)
    public_key = parse_pubkey_from_data(dns_data)

    print public_key
