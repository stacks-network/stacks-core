#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	Open Name System
	~~~~~

	:copyright: (c) 2014 by opennamesystem.org
	:license: MIT, see LICENSE for more details.
"""

import socket
import dns.resolver

#----------------------------------------
def dns_resolver(domain):

	import dns.name
	import dns.message
	import dns.query
	import dns.flags

	name_server = '8.8.8.8'
	ADDITIONAL_RDCLASS = 65535

	domain = dns.name.from_text(domain)
	if not domain.is_absolute():
		domain = domain.concatenate(dns.name.root)

	request = dns.message.make_query(domain, dns.rdatatype.ANY)
	request.flags |= dns.flags.AD
	request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
		dns.rdatatype.OPT, create=True, force_unique=True)
	
	data = dns.query.udp(request, name_server)

	return data

#----------------------------------------
def format_data(data):

	for reply in data.answer:

		reply = reply.to_text()
		answers = reply.rsplit('\n')

		for answer in answers: 
			print answer
