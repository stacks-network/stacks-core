#!/usr/bin/python

from setuptools import setup, find_packages

# to set __version__
exec(open('blockstack_client/version.py').read())

setup(
    name='blockstack-client',
    version=__version__,
    url='https://github.com/blockstack/blockstack-client',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Python client library for Blockstack',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    scripts=['bin/blockstack'],
    download_url='https://github.com/blockstack/blockstack-client/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'basicrpc==0.0.2',
        'virtualchain==0.0.9.0',
        'protocoin==0.1',
        'blockstack-profiles>=0.1.3',
        'pybitcoin>=0.9.8',
        'zone_file==0.1.6',
        'blockstack-storage-drivers>=0.0.1.0',
        'blockstack-utxo>=0.0.1.0',
        'defusedxml>=0.4.1',
        'keylib>=0.0.2'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
