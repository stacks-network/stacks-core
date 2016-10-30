#!/usr/bin/env python
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

exec(open("blockstack/version.py").read())

setup(
    name='blockstack-server',
    version=__version__,
    url='https://github.com/blockstack/blockack-server',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Name registrations on the Bitcoin blockchain with external storage',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    scripts=['bin/blockstack-server'],
    download_url='https://github.com/blockstack/blockstore/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'virtualchain>=0.14.0',
        'keychain>=0.1.4',
        'blockstack-client>=0.14.0',
        'defusedxml>=0.4.1',
        'pycrypto>=2.6.1',
        'simplejson>=3.8.2'
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
