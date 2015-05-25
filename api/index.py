from flask import render_template, send_from_directory
from . import app
from .utils import get_api_calls
from .ssl_required import ssl_required


@app.route('/')
def index():
    api_calls = get_api_calls('api/api_v1.md')
    return render_template('index.html', api_calls=api_calls)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')
