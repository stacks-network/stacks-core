
from . import app

@app.route('/')
def index():
	return "Onename API"

@app.route('/about')
def about():
	return 'Onename API'
