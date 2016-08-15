import os
import sys
import json
import argparse
import traceback
from api.auth import register_user


APP_ID = '39abc40158e78c6ae96c2a350401c56f'
APP_SECRET = 'd909fe1396accded7f7a3a449140ea5b6761605a1683d4df499fa583b406e541'


def init_db():
    register_user('ryan@shea.io', app_id=APP_ID, app_secret=APP_SECRET,
                  email_user=False)


def main():
    parser = argparse.ArgumentParser(
        description='Manage this Flask application.')
    parser.add_argument(
        'command', help='the name of the command you want to run')
    args = parser.parse_args()

    if args.command == 'init_db':
        init_db()
        print "database initialized!"
    else:
        raise Exception('Invalid command')

if __name__ == '__main__':
    main()
