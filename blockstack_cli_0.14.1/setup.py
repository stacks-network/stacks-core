
from setuptools import setup, find_packages

setup(
    name='blockstore',
    version='0.0.3',
    url='https://github.com/blockstack/blockstore-client',
    license='MIT',
    author='Onename',
    author_email='support@onename.com',
    description='Python client library to Blockstore',
    keywords='blockchain bitcoin btc cryptocurrency name key value store data',
    packages=find_packages(),
    scripts=['bin/blockstore-cli'],
    download_url='https://github.com/blockstack/blockstore-client/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'pybitcoin>=0.8.3',
        'kademlia>=0.2',
        'python-bitcoinrpc>=0.1',
        'jsonrpc>=1.2',
        'utilitybelt>=0.2.2'
        'virtualchain>=0.0.1'
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
