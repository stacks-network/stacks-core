#!/usr/bin/env python2

import scenarios
import traceback

try:
    from atlas_network import *
except ImportError, ie:
    traceback.print_exc()
    # older version of blockstack core
    pass
