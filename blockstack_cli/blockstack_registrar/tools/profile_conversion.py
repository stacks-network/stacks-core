#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

#-----------------------------------
def convert_v1_to_v2(profile):

	new_profile = {}
	
	if 'v' in profile:
		new_profile['v'] = '0.2'

	if 'website' in profile:
		new_profile['website'] = profile['website']
	
	if 'bio' in profile:
		new_profile['bio'] = profile['bio']
	
	if 'github' in profile:
		new_profile['github'] = profile['github']
	
	if 'instagram' in profile:
		new_profile['instagram'] = {"username":profile['instagram']}
	
	if 'twitter' in profile:
		new_profile['twitter'] = {"username":profile['twitter']}
	
	if 'cover' in profile:
		new_profile['cover'] = {"url":profile['cover']}

	if 'avatar' in profile:
		new_profile['avatar'] = {"url":profile['avatar']}

	if 'bitcoin' in profile:
		new_profile['bitcoin'] = {"address":profile['bitcoin']}

	if 'linkedin' in profile:
		new_profile['linkedin'] = {"url":profile['linkedin']}

	if 'name' in profile:
		new_profile['name'] = {"formatted":profile['name']}

	if 'facebook' in profile:
		new_profile['facebook'] = {"username":profile['facebook']}

	if 'location' in profile:
		new_profile['location'] = {"formatted":profile['location']}

	if 'angellist' in profile:
		new_profile['angellist'] = {"username":profile['angellist']}

	if 'bitmessage' in profile:
		new_profile['bitmessage'] = {"address":profile['bitmessage']}

	if 'pgp' in profile:
		new_profile['pgp'] = profile['pgp']

	return new_profile
