import re
import json
from flask import redirect, url_for, render_template, request
from . import app


def build_api_call_object(text):
    api_call = {}

    for section in text.split('\n\n'):
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
        r"""---START API CALL---.*?---END API CALL---\n""", re.DOTALL)

    with open(filename) as f:
        text = f.read()
        for s in re.findall(pattern, text):
            s = re.sub(r'---.*---\n', '', s)
            api_call = build_api_call_object(s)
            api_calls.append(api_call)

    return api_calls


@app.route('/')
def index():
    api_calls = get_api_calls('api/api_v1.md')

    return render_template('index.html', api_calls=api_calls)
