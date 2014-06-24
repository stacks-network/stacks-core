#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tools.onename_register import check_new_registrations
from tools.onename_activate import do_name_firstupdate

from time import sleep

POLLING_INTERVAL = 10

#-----------------------------------
if __name__ == '__main__':

	while(1):
		check_new_registrations()
		do_name_firstupdate()
		print "sleeping ... "
		sleep(POLLING_INTERVAL)
