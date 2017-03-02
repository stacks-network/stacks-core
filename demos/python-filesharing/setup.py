#!/usr/bin/env python

from setuptools import setup, find_packages

# to set __version__
exec(open('blockstack_files/version.py').read())

setup(
    name='blockstack-files',
    version=__version__,
    url='https://github.com/blockstack/blockstack-core',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Blockstack encrypted file sharing demo',
    keywords='blockchain git crypography name key value store data',
    packages=find_packages(),
    download_url='https://github.com/blockstack/blockstack-core/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    scripts=['bin/blockstack-files'],
    install_requires=[
        'blockstack>=0.14.1',
        'pyelliptic>=1.5.7',
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
