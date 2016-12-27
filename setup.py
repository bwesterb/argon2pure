#!/usr/bin/env python

import os
import sys
import os.path

from setuptools import setup

base_path = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(base_path, 'README.rst')) as f:
    with open(os.path.join(base_path, 'CHANGES.rst')) as g:
        long_description = '{0}\n{1}'.format(f.read(), g.read())

setup(
    name='argon2pure',
    version='1.3',
    description='Pure python implementation of the ARGON2 password hash',
    long_description=long_description,
    author='Bas Westerbaan',
    author_email='bas@westerbaan.name',
    url='http://github.com/bwesterb/argon2pure',
    license='MIT',
    zip_safe=True,
    install_requires=['six'],
    py_modules=['argon2pure'],
    test_suite='test_argon2pure',
    tests_require=['argon2-cffi >= 16.3.0'],
    classifiers = [
            'Development Status :: 4 - Beta',
            'License :: OSI Approved :: MIT License',
            'Operating System :: POSIX',
            'Topic :: Security',
            'Programming Language :: Python :: 2.6',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3.2',
            'Programming Language :: Python :: 3.3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
        ],
    ),
