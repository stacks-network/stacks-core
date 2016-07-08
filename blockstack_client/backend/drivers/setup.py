#!/usr/bin/python

from setuptools import setup, find_packages

# to set __version__
exec(open('blockstack_storage_drivers/version.py').read())

setup(
    name='blockstack-storage-drivers',
    version=__version__,
    url='https://github.com/blockstack/blockstack-storage-drivers',
    license='MIT',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Back-end storage drivers for Blockstack',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    download_url='https://github.com/blockstack/blockstack-storage-drivers/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'boto>=2.38.0',
        'basicrpc>=0.0.2',
        'blockstack_zones>=0.1.6',
        'pybitcoin>=0.9.9'
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
