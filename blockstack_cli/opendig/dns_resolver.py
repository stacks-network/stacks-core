#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	OpenDig
	~~~~~

	:copyright: (c) 2014 by OpenNameSystem.org
	:license: MIT, see LICENSE for more details.
"""

import socket
import dns.resolver

from opendig import DNS_SERVERS

ADDITIONAL_RDCLASS = 65535

#----------------------------------------
def dns_resolver(domain):

	import dns.name
	import dns.message
	import dns.query
	import dns.flags

	domain = dns.name.from_text(domain)
	if not domain.is_absolute():
		domain = domain.concatenate(dns.name.root)

	request = dns.message.make_query(domain, dns.rdatatype.ANY)
	request.flags |= dns.flags.AD
	request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
		dns.rdatatype.OPT, create=True, force_unique=True)
	
	data = dns.query.udp(request, DNS_SERVER[0])

	return data

#----------------------------------------
def json_data(data):

	#there is no real JSON standard for DNS data
	#it'd be nice to return json data

	#for reply in data.answer:
	#	reply = reply.to_text()
	#	answers = reply.rsplit('\n')
	#	for answer in answers: 
	#		print answer

	return data