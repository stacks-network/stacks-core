from flask import redirect, url_for, render_template, request

from . import app

@app.route('/')
def index():
	return redirect('/docs')
