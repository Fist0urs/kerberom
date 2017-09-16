# -*- coding: utf-8 -*-

import os
import codecs
from setuptools import setup, find_packages
import pkgutil
import sys


# Save version and author to __meta__.py
version = open('VERSION').read().strip()
dirname = os.path.dirname(__file__)
path = os.path.join(dirname, 'src', u'rom', '__meta__.py')
meta = '''# Automatically created. Please do not edit.
__version__ = '%s'
__author__ = u'Fist0urs'
''' % version
with open(path, 'w') as F:
	F.write(meta)

setup(
	# Basic info
	name=u'kerberom',
	version=version,
	author='Fist0urs',
	author_email='jean-christophe.delaunay@synacktiv.com',
	url='https://github.com/Fist0urs/kerberom',
	licence='BEER-WARE',
	description="Retrieve ARC4-HMAC'ed encrypted Tickets Granting Service on Active Directory",
	long_description=codecs.open('README.md', 'rb', 'utf8').read(),

	# Classifiers (see https://pypi.python.org/pypi?%3Aaction=list_classifiers)
	classifiers=[
		'Development Status :: Beta',
		'Intended Audience :: Information Security',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
	],

	# Packages and dependencies
	package_dir={'': 'src'},
	packages=find_packages('src'),
	install_requires=[
		"pyasn1==0.2.3",
		"ldap3"
	],

	# Other configurations
	zip_safe=False,
	platforms='any',
	# entry points
	entry_points={
		'console_scripts': [
			'kerberom = rom.__main__:main'
		]
	}
)
