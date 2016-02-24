#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import json


def json_stable_serialize(json_data):
    """
    Serialize a dict to JSON, but ensure that key/value pairs are serialized
    in a predictable, stable, total order.
    """

    if isinstance(json_data, list) or isinstance(json_data, tuple):
        json_serialized_list = []
        for json_element in json_data:
            json_serialized_list.append(json_stable_serialize(json_element))

        return "[" + ", ".join(json_serialized_list) + "]"

    elif isinstance(json_data, dict):
        json_serialized_dict = {}
        for key in json_data.keys():
            json_serialized_dict[key] = json_stable_serialize(json_data[key])

        key_order = [k for k in json_serialized_dict.keys()]
        key_order.sort()

        return "{" + ", ".join(['"%s": %s' % (k, json_serialized_dict[k]) for k in key_order]) + "}"

    elif isinstance(json_data, str) or isinstance(json_data, unicode):
        return '"' + json_data + '"'

    return '"' + str(json_data) + '"'
