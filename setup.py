
from setuptools import setup, find_packages

setup(
    name='openname',
    version='0.0.1',
    url='https://github.com/openname/opennamed',
    license='MIT',
    author='Onename',
    author_email='hello@halfmoonlabs.com',
    description='',
    keywords='bitcoin btc cryptocurrency',
    packages=find_packages(),
    scripts=['bin/opennamed', 'bin/openname-cli'],
    download_url='https://github.com/openname/openname/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'coinkit>=0.7.7',
        'kademlia>=0.2',
        'python-bitcoinrpc>=0.1',
        'txjson-rpc>=0.3'
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
