#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

from setuptools import setup, find_packages
import os

exec(open("blockstack_client/version.py").read())

setup(
    name='blockstack',
    version=__version__,
    url='https://github.com/blockstack/blockstack-core',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Name registrations on the Bitcoin blockchain with external storage',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    scripts=['bin/blockstack-server', 'bin/blockstack-core', 'bin/blockstack-snapshots',
             'bin/blockstack', 'bin/blockstack-subdomain-registrar'],
    download_url='https://github.com/blockstack/blockstore/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'virtualchain>=0.17.0',
        'keychain>=0.14.2.0',
        'protocoin>=0.2',
        'blockstack-profiles>=0.14.1',
        'blockstack-zones>=0.14.3',
        'defusedxml>=0.4.1',
        'keylib>=0.1.1',
        'simplejson>=3.8.2',
        'jsonschema>=2.5.1',
        'jsontokens>=0.0.4',
        'scrypt>=0.8.0',
        'jsonpointer>=1.14',
        'pyparsing>=2.2.0',     # not required, but causes problems if not installed properly
        'basicrpc>=0.0.2',      # DHT storage driver
        'boto>=2.38.0',         # S3 storage driver
        'dropbox>=7.1.1',       # Dropbox driver
        'pydrive>=1.3.1',       # Google Drive driver
        'onedrivesdk>=1.1.8',   # Microsoft OneDrive driver
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)

