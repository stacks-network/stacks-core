# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

from flask import render_template, redirect, url_for

from . import app

@app.route('/docs', defaults={'path': ''})
@app.route('/docs/<path:path>')
def docs(path):
	return render_template('docs.html')

@app.route('/')
def index():
	return redirect(url_for('docs'))

@app.route('/about')
def about():
	return render_template('about.html')
