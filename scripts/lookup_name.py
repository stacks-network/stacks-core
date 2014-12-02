import argparse
from pyopenname import *

def main():
    parser = argparse.ArgumentParser(description='Process a name')
    parser.add_argument('name', metavar='N')
    args = parser.parse_args()

    name = args.name

    db = NameDb('data/namespace.txt', 'data/content.txt')

    print lookup_name(name, db)

if __name__ == '__main__':
    main()