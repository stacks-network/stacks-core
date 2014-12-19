
from setuptools import setup, find_packages

setup(
    name='opennamelib',
    version='0.1.0',
    url='https://github.com/openname/opennamed',
    license='MIT',
    author='Onename',
    author_email='hello@halfmoonlabs.com',
    description='',
    keywords='bitcoin btc cryptocurrency',
    packages=find_packages(),
    scripts=['bin/opennamed', 'bin/openname-cli'],
    data_files=['opennamed.py',
                'openname_cli.py'],  # hack for including files from main dir
    download_url='https://github.com/openname/opennamed/archive/master.zip',
    zip_safe=False,
    install_requires=[
        'coinkit>=0.7.4',
        'kademlia>=0.2',
        'python-daemon>=1.6.1',
        'python-bitcoinrpc>=0.1',
        'zerorpc>=0.4.4'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
