#!/usr/bin/env python

from setuptools import setup, find_packages

# to set __version__
exec(open('blockstack_integration_tests/version.py').read())

setup(
    name='blockstack-integration-tests',
    version=__version__,
    url='https://github.com/blockstack/blockstack-integration-tests',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Integration tests for Blockstack Server, Blockstack Client, and other supporting infrastructure',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    scripts=[
        'bin/blockstack-test-scenario',
        'bin/blockstack-test-check-serialization',
        'bin/blockstack-test-all'
    ],
    download_url='https://github.com/blockstack/blockstack-integration-tests/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'virtualchain>=0.14.1',
        'blockstack-core>=0.14.1',
        'blockstack-profiles>=0.14.1',
        'blockstack-file>=0.14.0',
        'blockstack-gpg>=0.14.1',
        'blockstack-zones>=0.14.1'
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
