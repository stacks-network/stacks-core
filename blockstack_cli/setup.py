# -*- coding: utf-8 -*-
"""
    OpenDig
    ~~~~~

    :copyright: (c) 2014 by OpenNameSystem.org
    :license: MIT, see LICENSE for more details.
"""

from setuptools import setup

setup(
    name='opendig',
    version='0.1.0',
    url='https://github.com/opennamesystem/opendig',
    license='MIT',
    author='Muneeb Ali (@muneeb), Ryan Shea (@ryaneshea)',
    author_email='hello@halfmoonlabs.com',
    description="A command-line tool for the Open Name System (the equivalent of dig for DNS).",
    packages=['opendig'],
    scripts=['bin/opendig'],
    zip_safe=False,
    download_url='https://github.com/opennamesystem/opendig/archive/master.zip',
    install_requires=['cement==2.2.2','dnspython==1.11.1','coinrpc==0.1.0'],
    keywords=['domain', 'name', 'resolution', 'bitcoin', 'address'],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
)
