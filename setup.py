
from setuptools import setup

setup(
    name='pyopenname',
    version='0.1.0',
    url='https://github.com/openname/pyopenname',
    license='MIT',
    author='Onename',
    author_email='hello@halfmoon.io',
    description='',
    keywords='bitcoin btc cryptocurrency',
    packages=[
        'pyopenname'
    ],
    zip_safe=False,
    install_requires=[
        'coinkit>=0.7.4',
        'utilitybelt>=0.2.1'
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