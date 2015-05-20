from flask import render_template
from . import app
from .utils import get_api_calls


@app.route('/')
def index():
    api_calls = get_api_calls('api/api_v1.md')
    return render_template('index.html', api_calls=api_calls)
