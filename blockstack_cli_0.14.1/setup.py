#!/usr/bin/python

from setuptools import setup, find_packages
from blockstore_client.config import VERSION

setup(
    name='blockstore-client',
    version=VERSION,
    url='https://github.com/blockstack/blockstore-client',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Python client library for Blockstore',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    scripts=['bin/blockstore-cli'],
    download_url='https://github.com/blockstack/blockstore-client/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'pybitcoin>=0.9.7',
        'boto>=2.38.0',
        'basicrpc>=0.0.1',
        'bitcoin>=1.1.39'
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
