Demo: Blockstack-files
======================

CLI program for loading and storing files with Blockstack's RESTful API.

Sample usage, once completed:

```
$ pwd
python-filesharing
$ ls
README.md
bin
blockstack_files
blockstack_files.egg-info
build
dist
setup.py
$ blockstack-files login PASSWORD
$ blockstack-files ls /

$ blockstack-files mkdir /foo
$ blockstack-files ls /
foo/
$ blockstack-files mkdir /bar
$ blockstack-files ls /
bar/
foo/
$ blockstack-files put ./setup.py /foo/setup.py
$ blockstack-files ls /
bar/
foo/
$ blockstack-files ls /foo
setup.py
$ blockstack-files cat /foo/setup.py
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

$ blockstack-files rm /foo/setup.py
$ blockstack-files ls /foo

$ blockstack-files ls /
bar/
foo/
$ blockstack-files rmdir /foo
$ blockstack-files rmdir /bar
$ blockstack-files ls /

$
```
