#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

from .register import update_name
from commontools import log 

import json 

from time import sleep

from coinrpc import namecoind 

#-----------------------------------
def get_overlap():
	
	reply = namecoind.name_filter('id/')
	
	counter = 0 

	id_namespace = []

	for i in reply:
		if 'expired' in i:
			pass
		else:
			counter += 1
			id_namespace.append(i['name'].lstrip('id/'))
	
	reply = namecoind.name_filter('u/')

	counter = 0 

	u_namespace = []

	for i in reply:
		if 'expired' in i:
			pass
		else:
			counter += 1
			u_namespace.append(i['name'].lstrip('u/'))

	from collections import Counter 
	a_multiset = Counter(id_namespace)
	b_multiset = Counter(u_namespace)

	overlap = list((a_multiset & b_multiset).elements())

	for i in overlap:
		print i
	print len(overlap)


#-----------------------------------
def get_expiring_names(regrex,expires_in):

	expiring_names = [] 
	reply = namecoind.name_filter(regrex)

	counter_total = 0
	counter_expiring = 0
	for i in reply:
		counter_total += 1 
		try:
			if i['expires_in'] < expires_in:
				expiring_names.append(i)
				print i['name']
				print i['expires_in']
				counter_expiring += 1
				#print i['value']
				#print '-' * 5
		except:
			print i 
	
	print '-' * 5
	print "Total names: " + str(counter_total)
	print "Total expiring in " + str(expires_in) + " blocks: " + str(counter_expiring)

	return expiring_names

#-----------------------------------
def get_expired_names(regrex):

	expired_names = [] 
	reply = namecoind.name_filter(regrex,check_blocks=0)

	counter_total = 0
	counter_expired = 0
	for i in reply:
		counter_total += 1 
		
		if 'expired' in i and i['expired'] == 1: 
			print i['name']
			counter_expired += 1

			expired_names.append(i)
	
	print '-' * 5
	print "Total names: " + str(counter_total)
	print "Total expired: " + str(counter_expired)

	return expired_names 

#-----------------------------------
def send_update(expiring_users):

	for i in expiring_users:
		key = i['name']
		try:
			value = json.loads(i['value'])
		except:
			value = i['value']

		if 'message' in value:
			value['message'] = value['message'].replace('This OneName username','This username')
		
			#print key
			#print value 
			#print '-' * 5

			try:
				update_name(key,value)
			except Exception as e:

				if hasattr(e, 'error'):
					print e.error
				else:
					print e 
			
			sleep(5)
			
#-----------------------------------
if __name__ == '__main__':

	expiring_users = get_expiring_names('u/',2000)
	#get_expired_names('u/')
	#send_update(expiring_users)