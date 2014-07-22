"""
OpenDig
==============

"""

from setuptools import setup

setup(
    name='opendig',
    version='0.1.0',
    url='https://github.com/opennamesystem/opendig',
    license='MIT',
    author='Muneeb Ali, Ryan Shea',
    author_email='hello@halfmoonlabs.com',
    description="Command-line tool for Open Name System (like dig is for DNS)",
    packages=['opendig'],
    scripts=['bin/opendig'],
    zip_safe=False,
    install_requires=[
        'cement>=2.2.2',
        'dnspython>=1.11.1'
    ],
    keywords = ['domain', 'name', 'resolve', 'bitcoin', 'address'],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
)