#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack Core
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack Core.

    Blockstack Core is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack Core is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack Core. If not, see <http://www.gnu.org/licenses/>.
"""

import re
import json
from .config import MAX_PROFILE_LIMIT
from .config import MEMCACHED_ENABLED, MEMCACHED_SERVERS, MEMCACHED_USERNAME, MEMCACHED_PASSWORD

from flask import make_response
from functools import wraps
from collections import OrderedDict

def cache_control(timeout):
    def decorator(f):
        @wraps(f)
        def decorated_f(*a, **kw):
            resp = make_response(f(*a, **kw))
            resp.headers['Cache-Control'] = 'public, max-age={:d}'.format(timeout)
            return resp
        return decorated_f
    return decorator

def get_mc_client():
    """ Return a new connection to memcached
    """
    if not MEMCACHED_ENABLED:
        return False

    import pylibmc

    mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                        username=MEMCACHED_USERNAME,
                        password=MEMCACHED_PASSWORD,
                        behaviors={"no_block": True,
                                   "connect_timeout": 200})
    return mc


def build_api_call_object(text):
    api_call = {}

    first_line, text = text.split('\n', 1)
    api_call['title'] = first_line

    for section in text.split('\n\n#### '):
        section = section.replace('#### ', '')
        if ':\n' in section:
            key, value = section.split(':\n', 1)
            value = value.strip()
            if '[]' in key:
                key = key.replace('[]', '')
                parts = value.split('\n')
                value = []
                for part in parts:
                    json_part = json.loads(part)
                    value.append(json_part)
            api_call[key.strip()] = value

    return api_call

class MarkdownGroup:
    def __init__(self):
        self.notes = False
        self.subgroups = OrderedDict()
    def add_to_group(self, obj, subgroup):
        if not subgroup in self.subgroups:
            self.subgroups[subgroup] = []
        self.subgroups[subgroup].append(obj)

def write_markdown_spec(f_out, api_calls):
    groups = OrderedDict()
    
    for api_obj in api_calls:
        obj = {}
        obj["Method"] = api_obj["title"]
        obj["API Call"] = "{} {}".format(api_obj["method"],
                                         api_obj["path_template"])
        obj["Grouping"] = api_obj["grouping"]
        obj["Notes"] = api_obj["notes"] if "notes" in api_obj else ""
        obj["API Family"] = api_obj["family"] if "family" in api_obj else "-"
        obj["Subgroup"] = api_obj["subgroup"] if "subgroup" in api_obj else ""
        
        if obj["Grouping"] not in groups:
            groups[obj["Grouping"]] = MarkdownGroup()
        groups[obj["Grouping"]].add_to_group(obj, obj["Subgroup"])

        if "grouping_note" in api_obj:
            groups[obj["Grouping"]].notes = api_obj["grouping_note"]

    row_headers = ["Method", "API Call", "API Family", "Notes"]


    f_out.write("# Blockstack Specifications\n\n")
    for gname, g in groups.items():
        f_out.write("## {}\n\n".format(gname))
        for sg_name, sg in g.subgroups.items():
            if len(sg_name) > 0:
                f_out.write("### {}\n\n".format(sg_name))
            f_out.write("| {} |\n".format(" | ".join(row_headers)))
            f_out.write("| {} |\n".format(" | ".join(["----" for i in row_headers])))
            for item in sg:
                f_out.write("| {} |\n".format(" | ".join(
                    [item[k] for k in row_headers])))
        f_out.write("\n\n")
        if g.notes:
            f_out.write("#### {}\n\n".format(g.notes))

def get_api_calls(filename):
    api_calls = []

    pattern = re.compile(
        r"""\n## .*?_end_""", re.DOTALL)

    with open(filename) as f:
        text = f.read()
        for match in re.findall(pattern, text):
            match = re.sub(r'\n## ', '', match)
            match = re.sub(r'\n_end_', '', match)
            api_call = build_api_call_object(match)
            api_calls.append(api_call)

    return api_calls


def camelcase_to_snakecase(name):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def utf8len(s):
    if type(s) == unicode:
        return len(s)
    else:
        return len(s.encode('utf-8'))


def zone_file_is_too_big(profile):
    if utf8len(json.dumps(profile)) > MAX_PROFILE_LIMIT:
        return True
    else:
        return False
