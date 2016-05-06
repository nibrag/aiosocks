#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
        name='aiosocks',
        author='Nail Ibragimov',
        version='0.1.1',
        license='LICENSE.txt',
        url='https://github.com/nibrag/aiosocks',

        description='SOCKS proxy client for asyncio and aiohttp',
        long_description=open("README.md").read(),
        packages=['aiosocks']
)
