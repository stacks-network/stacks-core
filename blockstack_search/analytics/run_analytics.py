#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
	run basic analytics
'''


import os 
import json

from pymongo import MongoClient
client = MongoClient()

db = client['onename_user_db']
local_users = db.users 
search_stats = db.search_stats

from datetime import datetime, timedelta
day = timedelta(days=1)
launch = datetime(year=2014,month=03,day=03)
search_launch = datetime(year=2014,month=07,day=26)

#-----------------------------------

MONGODB_URI = os.environ['MONGODB_URI']
OLD_DB = os.environ['OLD_DB']

remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user

old_client = MongoClient(OLD_DB)
old_db = old_client.get_default_database()
old_users = old_db.user

#-----------------------------------
def get_old_db_users():

	github_count = 0
	twitter_count = 0
	website_count = 0
	bio_count = 0
	counter = 0

	for i in old_users.find(): 
		new_user = {}
		new_user['username'] = i['username']
		new_user['profile'] = i['profile']
		new_user['created_at'] = i['created_at']
		#print new_user
		#print '----'
		profile = json.loads(i['profile'])

		if 'github' in profile:
			github_count += 1
		elif 'twitter' in profile:
			twitter_count += 1
		elif 'website' in profile:
			website_count += 1
		elif 'bio' in profile:
			bio_count += 1

		counter += 1

		if counter % 100 == 0:
			print counter

		if REFRESH:
			local_users.insert(new_user)

	print '-' * 5
	print "Total users registered: " + str(counter) 
	print "Users with github accounts: " + str(github_count)
	print "Users with twitter accounts: " + str(twitter_count)
	print "Users with websites: " + str(website_count)
	print "Users with bios: " + str(bio_count)
	print '-' * 5

	return counter

#-----------------------------------
def remove_duplicates():

	counter = 0 

	for i in users.find():

		username = i['username']

		temp = local_users.find_one({"username":username})

		if temp is not None:
			#print temp['username']
			local_users.remove(temp)
			counter += 1

	print "Duplicates: " + str(counter)

	return counter

#-----------------------------------
def drop_db():
	client.drop_database('onename_user_db')

#-----------------------------------
def get_new_db_users():

	github_count = 0
	twitter_count = 0
	website_count = 0
	bio_count = 0
	counter = 0

	for i in users.find(): 
		new_user = {}
		new_user['username'] = i['username']
		new_user['profile'] = i['profile']
		new_user['created_at'] = i['created_at']
		#print new_user
		#print '----'
		profile = i['profile']

		if 'github' in profile:
			github_count += 1
		elif 'twitter' in profile:
			twitter_count += 1
		elif 'website' in profile:
			website_count += 1
		elif 'bio' in profile:
			bio_count += 1

		counter += 1

		if counter % 100 == 0:
			print counter

		if REFRESH:
			#pass
			local_users.insert(new_user)

	print '-' * 5
	print "Total users registered: " + str(counter) 
	print "Users with github accounts: " + str(github_count)
	print "Users with twitter accounts: " + str(twitter_count)
	print "Users with websites: " + str(website_count)
	print "Users with bios: " + str(bio_count)
	print '-' * 5

	return counter

#---------------------------------
def get_btc_address():

	counter = 0 

	fout = open('output_file','w')

	for user in local_users.find():

		try:
			profile = json.loads(user['profile'])
		except:
			profile = user['profile']

		if 'bitcoin' in profile:
			if 'address' in profile['bitcoin']:
				try:
					fout.write(profile['bitcoin']['address'] + '\n')
					counter += 1

				except:
					pass
				
	print counter

import requests
import json  

#---------------------------------
def make_local_db():

	drop_db()

	num_old_users = get_old_db_users()

	num_duplicates = remove_duplicates()

	num_new_users = get_new_db_users()

	final_users = num_old_users + num_new_users - num_duplicates

	print "total users: " + str(final_users)

#---------------------------------
def get_growth_rate():

	growth_rate = []
	counter = 0
	days = 0
	current_date = launch
	finish_date = datetime.now()

	while(current_date < finish_date):

		counter = 0

		for user in local_users.find(): 

			if current_date + day > user['created_at']:
				counter += 1

		print counter
		current_date = current_date + day
		days += 1
		growth_rate.append(counter)
		
		#print current_date
		#print '-' * 5
			

	print growth_rate
	#print days
		
#---------------------------------
def get_verification_rate():

	growth_rate = []
	counter = 0
	days = 0
	current_date = launch
	finish_date = datetime.now()

	while(current_date < finish_date):

		counter = 0

		for user in local_users.find():

			try:
				profile = json.loads(user['profile'])
			except:
				profile = user['profile']

			num_verify = 0 

			if 'twitter' in profile:
				if 'proof' in profile['twitter']:
					num_verify += 1

			if 'github' in profile:
				if 'proof' in profile['github']:
					num_verify += 1

			if 'facebook' in profile:
				if 'proof' in profile['facebook']:
					num_verify += 1

			if num_verify == 0:
				continue

			if current_date + day > user['created_at']:
				counter += num_verify
				

		print counter
		growth_rate.append(counter)

		current_date = current_date + day
		days += 1
	
	print growth_rate
	print days
	#import matplotlib.pyplot as plt
	#plt.plot(growth_rate)
	#plt.show()

#-----------------------------------
def parse_search():

	with open('data/logs/access.log.20140727-053029', 'r') as readfile:

		for line in readfile.readline():

			line = line.rsplit(' ')

			query = line[6]
		
			date = line[3].lstrip('[').rsplit('/')

			month = 1
			if date[1] == 'Jul':
				month = 7
			elif date[1] == 'Aug':
				month = 8

			search_day = datetime(day=int(date[0]),month=month,year=2014)

			post = {} 
			post['query'] = query 
			post['date'] = search_day
			print post
			search_stats.save(post)

#-----------------------------------
def plot_graphs():

	#total_users = [16, 19, 31, 39, 45, 48, 53, 2648, 3733, 3956, 4081, 4305, 4372, 4518, 4598, 4657, 4757, 4796, 4848, 4907, 5038, 5080, 5124, 5145, 5800, 6187, 6355, 6440, 6529, 6636, 6691, 6748, 6827, 6871, 6893, 6966, 6984, 7000, 7007, 7013, 7020, 7051, 7060, 7074, 7098, 7132, 7151, 7163, 7167, 7181, 7195, 7206, 7228, 7236, 7241, 7246, 7260, 7275, 7301, 7319, 7332, 7336, 7346, 7448, 7524, 7568, 7594, 7610, 7617, 7635, 7660, 7672, 7692, 7726, 7733, 7738, 7747, 7767, 7789, 7823, 7838, 7855, 7862, 7863, 7866, 7880, 7888, 7895, 7902, 7905, 7911, 7913, 7921, 7928, 7937, 7946, 7952, 7954, 7958, 7966, 7982, 7992, 7997, 7999, 8002, 8004, 8016, 8027, 8033, 8038, 8039, 8042, 8048, 8059, 8070, 8075, 8097, 8106, 8118, 8166, 8255, 8284, 8307, 8328, 8340, 8373, 8412, 8768, 9071, 9142, 9175, 9193, 9245, 9405, 9510, 9568, 9597, 9621, 9648, 9669, 9731, 9752, 9822, 9932, 9960, 9999, 10041, 10055, 10146, 10176, 10200, 10386, 10486, 10641, 10735, 10771, 10822, 11031, 11316, 11809, 12171, 12400, 12496, 12587, 12823, 13064]
	#users_verified = [0, 0, 0, 0, 0, 0, 0, 7, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 15, 17, 17, 19, 19, 22, 23, 23, 23, 24, 24, 24, 24, 24, 25, 26, 26, 26, 26, 27, 27, 27, 28, 28, 28, 29, 29, 30, 30, 30, 30, 30, 30, 30, 31, 32, 32, 33, 33, 33, 33, 34, 34, 34, 34, 35, 35, 35, 35, 35, 35, 35, 36, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39, 40, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 44, 50, 59, 82, 88, 97, 102, 105, 122, 133, 236, 324, 347, 363, 368, 386, 456, 495, 520, 534, 544, 551, 562, 585, 588, 618, 658, 674, 689, 704, 709, 744, 757, 765, 827, 870, 940, 976, 990, 1003, 1084, 1197, 1376, 1505, 1607, 1646, 1687, 1775, 1814]
	#total_verified = [0, 0, 0, 0, 0, 0, 0, 11, 14, 14, 14, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 22, 26, 26, 29, 29, 36, 38, 38, 38, 39, 39, 39, 39, 39, 41, 42, 42, 42, 42, 43, 43, 43, 44, 44, 44, 45, 45, 46, 46, 46, 46, 46, 46, 46, 48, 50, 50, 52, 52, 52, 52, 53, 53, 53, 53, 54, 54, 54, 54, 54, 54, 54, 55, 57, 57, 59, 59, 59, 59, 59, 59, 59, 59, 61, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 67, 75, 91, 125, 132, 144, 150, 153, 179, 194, 312, 425, 455, 475, 481, 506, 597, 645, 681, 702, 715, 723, 734, 762, 766, 813, 869, 892, 913, 931, 941, 991, 1011, 1021, 1122, 1184, 1283, 1339, 1363, 1387, 1556, 1768, 2090, 2315, 2492, 2568, 2625, 2739, 2796]

	import matplotlib.pyplot as plt

	p1 = plt.plot(total_users,color="blue")
	#p2 = plt.plot(total_verified,color="red")
	plt.legend(["total users"],loc='upper left')
	plt.yticks(range(0,13500,500))
	plt.xlabel('Days')
	#plt.show()
	plt.savefig('total_users.pdf')
	
#-----------------------------------
if __name__ == '__main__':

	#parse_search() 

	#get_growth_rate()

	#get_btc_address()

	make_local_db()

	#get_verification_rate()

	#print "read instructions before running"