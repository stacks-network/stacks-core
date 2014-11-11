#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
	Openname-resolver
	~~~~~

	:copyright: (c) 2014 by OpenNameSystem.org
	:license: MIT, see LICENSE for more details.
"""

import os
from server.openname_resolver import app
from server.config import DEFAULT_HOST, DEFAULT_PORT, DEBUG

#------------------------------
def runserver():

	port = int(os.environ.get('PORT', DEFAULT_PORT))
	app.run(host=DEFAULT_HOST, port=port, debug=DEBUG)

#------------------------------
if __name__ == '__main__':
	
	runserver()
