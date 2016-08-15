#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
from resolver.server import app
from resolver.config import DEFAULT_HOST, DEFAULT_PORT, DEBUG


# ------------------------------
def runserver():

    port = int(os.environ.get('PORT', DEFAULT_PORT))
    app.run(host=DEFAULT_HOST, port=port, debug=DEBUG)

# ------------------------------
if __name__ == '__main__':

    runserver()
