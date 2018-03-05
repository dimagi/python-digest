#!/usr/bin/env python
from __future__ import absolute_import
from __future__ import unicode_literals
from setuptools import setup

setup(
    name='python-digest',
    version='1.7',
    description=('A Python library to aid in implementing HTTP Digest Authentication.'),
    long_description=(
"""
"""
    ),
    author='Akoha Inc.',
    author_email='adminmail@akoha.com',
    url='http://bitbucket.org/akoha/python-digest/',
    packages=['python_digest'],
    package_dir={'python_digest': 'python_digest'},
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe=True,
)
