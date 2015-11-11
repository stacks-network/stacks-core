# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import re
import json
from .settings import MAX_PROFILE_LIMIT


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


def sizeInvalid(profile):

    if utf8len(json.dumps(profile)) > MAX_PROFILE_LIMIT:
        return True
    else:
        return False