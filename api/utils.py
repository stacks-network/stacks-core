#!/usr/bin/env python2
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

def profile_log(function):
    import blockstack_client.config as blockstack_config
    log = blockstack_config.get_logger()

    import cProfile, StringIO, pstats
    def wrapper(*a, **kw):
        pr = cProfile.Profile()
        pr.enable()
        out = function(*a, **kw)
        pr.disable()
        s = StringIO.StringIO()
        sortby = 'time'
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats(10)
        log.debug(s.getvalue())
        return out
    return wrapper

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

def run_api_to_markdown_specs(fn_in = 'api/api_v1.md', fn_out = '/tmp/api-specs.md'):
    with open(fn_out, 'w') as f_out:
        write_markdown_spec(f_out, get_api_calls(fn_in))

def write_markdown_spec(f_out, api_calls):
    """
    Translates from api_calls dictionary [returned from get_api_calls()]
    into a markdown spec (i.e., docs/api-specs.md)

    $ python -c "from api.utils import *; f = open('/tmp/foo', 'w'); write_markdown_spec(f, get_api_calls('api/api_v1.md')); f.close()"
    """
    groups = OrderedDict()
    
    for api_obj in api_calls:
        obj = {}
        obj["Method"] = api_obj["title"]
        obj["API Call"] = "{} {}".format(api_obj["method"],
                                         api_obj["path_template"])
        obj["Grouping"] = api_obj["grouping"]
        obj["Notes"] = api_obj["notes"] if "notes" in api_obj else ""
        obj["API Family"] = api_obj["family"] if "family" in api_obj else "-"
        obj["Subgroup"] = api_obj["subgrouping"] if "subgrouping" in api_obj else ""
        
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
            f_out.write("| {} |\n".format(" | ".join(["-------------" for i in row_headers])))
            for item in sg:
                f_out.write("| {} |\n".format(" | ".join(
                    [item[k] for k in row_headers])))
            f_out.write("\n")
        if g.notes:
            f_out.write("#### {}\n\n".format(g.notes))

def run_md_api_specs_to_api_detailed(fn_in = 'docs/api-specs.md', fn_out = 'api/api_v1.md'):
    with open(fn_in) as f_in:
        with open(fn_out, 'w') as f_out:
            md_api_specs_to_api_detailed(f_in, f_out)

def md_api_specs_to_api_detailed(f_in, f_out):
    group_header = re.compile(r"""^## (.*)$""", re.DOTALL)
    subgroup_header = re.compile(r"""^### (.*)$""", re.DOTALL)
    note_header = re.compile(r"""^#### (.*)$""", re.DOTALL)

    cur_group = None
    cur_subgroup = None
    cur_note = None
    cur_obj = None

    objects = []

    for line in f_in:
        line = line.strip()
        if cur_note:
            if line.startswith("|") or line.startswith("#"):
                cur_obj["grouping_note"] = "\n".join(cur_note)
                cur_note = None
            else:
                cur_note.append(line)

        matched_head = re.match(group_header, line)
        if matched_head:
            cur_group = matched_head.group(1)
            continue
        matched_subhead = re.match(subgroup_header, line)
        if matched_subhead:
            cur_subgroup = matched_subhead.group(1)
            continue
        matched_note_header = re.match(note_header, line)
        if matched_note_header:
            cur_note = [matched_note_header.group(1)]
            continue
        if line.startswith("|"):
            row_contents = line.split("|")[1:-1]
            if row_contents[0].startswith(" Method") or row_contents[0].startswith(" -"):
                continue
            else:
                if cur_obj:
                    objects.append(cur_obj)
                cur_obj = {}
                cur_obj["title"] = row_contents[0].strip()
                cur_obj["grouping"] = cur_group
                if cur_subgroup:
                    cur_obj["subgrouping"] = cur_subgroup
                cur_obj["notes"] = row_contents[3].strip()
                api_call = row_contents[1].strip()
                cur_obj["method"], cur_obj["path_template"] = api_call.split(" ")
                cur_obj["family"] = row_contents[2].strip()
                to_anchor_tag = cur_obj["title"].lower().replace(" ", "_").replace("the", "")
                to_anchor_tag = to_anchor_tag.replace("(", "_").replace("'", "").replace(")", "_")
                if len(to_anchor_tag) > 20:
                    to_anchor_tag = to_anchor_tag[:20]
                cur_obj["anchor_tag"] = to_anchor_tag
    if cur_note:
        cur_obj["grouping_note"] = "\n".join(cur_note)
    if cur_obj:
        objects.append(cur_obj)

    # now, we write the objects out to a MD file...
    f_out.write("# API Documentation\n\n")

    keys = ["grouping", "subgrouping", "anchor_tag", "description",
            "response_description", "notes", "family", "method",
            "path_template"] #, "tryit_pathname", "example_request_bash","example_response"]

    tryit_attempts = { "name" : "muneeb.id",
                       "blockchain" : "bitcoin",
                       "address" : "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP"}
    import requests

    for object in objects:
        f_out.write("## {}\n\n".format(object["title"]))
        for key in keys:
            if key in object:
                f_out.write("#### {}:\n{}\n\n".format(key, object[key]))
            else:
                f_out.write("#### {}\n\n\n".format(key))
        try:
            if object["method"] == "GET":
                path_template = object["path_template"]
                tryit_pathname = path_template.format(**tryit_attempts)
                get_url = "http://localhost:6270{}".format(tryit_pathname)
                example_response = json.dumps(requests.get(get_url).json(), indent = 2 )
                f_out.write("#### {}:\n{}\n\n".format("tryit_pathname", tryit_pathname))
                f_out.write("#### {}:\n{}\n\n".format("example_request_bash", tryit_pathname))
                f_out.write("#### {}:\n{}\n\n".format("example_response", example_response))
                print("example requested: {}".format(path_template))
        except Exception as e:
            pass
        f_out.write("_end_\n\n")

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
