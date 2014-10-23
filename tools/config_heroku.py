import os, sys, json, argparse, traceback

def run_heroku_command(command, app_name):
	os_command = command + " --app " + app_name
	os.system(os_command)
	return True

def config_heroku(secrets, app_name):
	command = "heroku config:set"

	for attr in dir(secrets):
		if attr[0] != '_':
			command += " " + attr + "=" + "'" + str(getattr(secrets, attr)) + "'"

	run_heroku_command(command, app_name)
	
	return True

class Secrets():
	pass

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Config Heroku vars from file with secret values.')
	parser.add_argument('app_name', metavar='N',
    	             	help='the name of the app to set config vars for')
	parser.add_argument('secretfile', metavar='S',
                   		help='the filename of the document with the secrets')
	args = parser.parse_args()

	secrets = Secrets()
	filename = args.secretfile
	with open(filename, 'r') as f:
		for line in f:
			if '=' in line:
				line = "secrets." + line
				exec(line)
	app_name = args.app_name

	config_heroku(secrets, app_name)