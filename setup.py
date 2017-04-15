#!/usr/bin/env python
import codecs
import os
import re
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with codecs.open(os.path.join(os.path.abspath(os.path.dirname(
        __file__)), 'aiosocks', '__init__.py'), 'r', 'latin1') as fp:
    try:
        version = re.findall(r"^__version__ = '([^']+)'\r?$",
                             fp.read(), re.M)[0]
    except IndexError:
        raise RuntimeError('Unable to determine version.')


if sys.version_info < (3, 5, 0):
    raise RuntimeError("aiosocks requires Python 3.5+")


setup(
        name='aiosocks',
        author='Nail Ibragimov',
        author_email='ibragwork@gmail.com',
        version=version,
        license='Apache 2',
        url='https://github.com/nibrag/aiosocks',

        description='SOCKS proxy client for asyncio and aiohttp',
        long_description=open("README.rst").read(),
        packages=['aiosocks']
)
