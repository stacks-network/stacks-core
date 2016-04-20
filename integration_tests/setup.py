#!/usr/bin/python

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
        'bin/cat-mock-bitcoind',
        'bin/blockstack-test-scenario',
        'bin/blockstack-test-all'
    ],
    download_url='https://github.com/blockstack/blockstack-integration-tests/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'virtualchain>=0.0.9.0',
        'blockstack-client>=0.0.13.0',
        'blockstack>=0.0.13',
        'blockstack-profiles>=0.1.3',
        'blockstack-storage-drivers>=0.0.1.0'
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
