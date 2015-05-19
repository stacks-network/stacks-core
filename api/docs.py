from flask import redirect, url_for, render_template, request
from . import app
from .api_calls import api_calls


@app.route('/')
def index():
    return render_template('index.html', api_calls=api_calls)
