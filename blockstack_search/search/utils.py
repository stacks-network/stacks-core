#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Search.

    Search is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Search is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Search. If not, see <http://www.gnu.org/licenses/>.
"""

import json
import re

from json import JSONEncoder
import logging
from config import DEBUG


def get_logger(log_name=None, log_type='stream'):

    if(DEBUG):
        log = logging.getLogger(log_name)
        log.setLevel(logging.DEBUG)

        formatter_stream = logging.Formatter('[%(levelname)s] %(message)s')
        handler_stream = logging.StreamHandler()
        handler_stream.setFormatter(formatter_stream)

        log.addHandler(handler_stream)

    else:
        log = None

    return log

# common logger
log = get_logger()

"""
from bson.objectid import ObjectId
class MongoEncoder(JSONEncoder):
    def default(self, obj, **kwargs):
        if isinstance(obj, ObjectId):
            return str(obj)
        else:
            return JSONEncoder.default(obj, **kwargs)
"""


def pretty_dump(input):

    return json.dumps(input, sort_keys=True, indent=4,
                      separators=(',', ': '))


def pretty_print(input):
    print pretty_dump(input)


def error_reply(msg):
    reply = {}
    reply['status'] = -1
    reply['message'] = "ERROR: " + msg
    return pretty_dump(reply)


def get_json(data):

    if isinstance(data, dict):
        pass
    else:
        try:
            data = json.loads(data)
        except:
            return error_reply("input data is not JSON")

    return data


def validUsername(username):

    a = re.compile("^[a-z0-9_]{1,60}$")

    if a.match(username):
        return True
    else:
        return False
