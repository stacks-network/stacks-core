#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack:

    This installs blockstack-server and blockstack-cli
"""

from setuptools import setup, find_packages
import sys
import os

setup(
    name='blockstack',
    version='0.0.10.9',
    url='https://github.com/blockstack/blockstack',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Decentralized naming and storage secured by the blockchain',
    keywords='blockchain bitcoin btc cryptocurrency name domain naming system data',
    download_url='https://github.com/blockstack/blockstack/archive/master.zip',
    zip_safe=False,
    install_requires=[
        'blockstore==0.0.10.10',
        'registrar==0.0.3.10',
        'blockstack-client==0.0.12.7',
        'cachetools==1.1.6',
        'base58==0.2.2'
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