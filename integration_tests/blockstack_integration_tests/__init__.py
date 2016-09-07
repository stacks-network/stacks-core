#!/usr/bin/env python

import scenarios

try:
    from atlas_network import *
except ImportError:
    # older version of blockstack core
    pass
