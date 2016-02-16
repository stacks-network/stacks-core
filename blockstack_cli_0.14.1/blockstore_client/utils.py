#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore-client.

    Blockstore-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore-client. If not, see <http://www.gnu.org/licenses/>.
"""

import json

from config import log


def pretty_dump(data):
    """ format data
    """

    if type(data) is list:

        if len(data) == 0:
            # we got an empty array
            data = {}
        else:
            # Netstring server responds with [{data}]
            log.debug("converting [] to {}")
            data = data[0]

    if type(data) is not dict:
        try:
            data = json.loads(data)
        except Exception as e:
            # data is not valid json, convert to json
            data = {'result': data}

    return json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))


def print_result(json_str):
    data = pretty_dump(json_str)

    if data != "{}":
        print data
