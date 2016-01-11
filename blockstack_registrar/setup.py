#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

from setuptools import setup, find_packages

setup(
    name='registrar',
    version='0.0.3',
    url='https://github.com/blockstack/registrar',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='For bulk registrations and updates of blockchain ID',
    keywords='blockchain bitcoin BTC cryptocurrency name registrations DHT',
    packages=find_packages(),
    scripts=['bin/registrar'],
    download_url='https://github.com/blockstack/registrar/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'keychain>=0.1.4',
        'basicrpc>=0.0.2',
        'pymongo>=3.0.3',
        'pycrypto>=2.6.1',
        'blockstore-client>=0.0.10',
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
