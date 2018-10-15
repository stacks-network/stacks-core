#!/usr/bin/env python2

from setuptools import setup, find_packages

# to set __version__
exec(open('blockstack_integration_tests/version.py').read())

print 'version = {}'.format(__version__)

setup(
    name='blockstack-integration-tests',
    version=__version__,
    url='https://github.com/blockstack/blockstack-integration-tests',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Integration tests for Blockstack packages',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    scripts=[
        'bin/blockstack-test-scenario',
        'bin/blockstack-test-check-serialization',
        'bin/blockstack-test-all',
        'bin/blockstack-test-all-junit',
        'bin/blockstack-test-env',
        'bin/blockstack-netlog-server',
    ],
    download_url='https://github.com/blockstack/blockstack-integration-tests/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'blockstack>=0.20.0',
        'xmlrunner>=1.7.7',
        'influxdb>=4.1.1',

        # hold-overs for blockstack_client
        'jsonpointer>=1.14',
        'pyparsing>=2.2.0',     # not required, but causes problems if not installed properly
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
