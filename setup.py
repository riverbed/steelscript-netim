# Copyright (c) 2019-2024 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from glob import glob

from setuptools import setup, find_packages

setup_args = {
    'name':               'steelscript.netim',
    'version':            '24.11.1',
    'author':             'Riverbed Community',
    'author_email':       'community@riverbed.com',
    'url':                'https://community.riverbed.com',
    'license':            'MIT',
    'description':        'Python module for interacting with Riverbed '
                          'NetIM with SteelScript',

    'long_description': '''SteelScript for NetIM
===========================
SteelScript is a collection of libraries and scripts in Python and JavaScript
for interacting with Riverbed Technology devices.
For a complete guide to installation, see:
https://support.riverbed.com/apis/steelscript
    ''',

    'platforms': 'Linux, Mac OS, Windows',

    'classifiers': [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.12',
        'Topic :: System :: Networking',
    ],

    'packages': find_packages(exclude=('gitpy_versioning',)),

    'data_files': (
        ('share/doc/steelscript/docs/netim', glob('docs/*')),
        ('share/doc/steelscript/examples/netim', glob('examples/*')),
        ('share/doc/steelscript/notebooks/netim', glob('notebooks/*')),
    ),

    'install_requires': (
        'steelscript>=24.2.0',
    ),

    'extras_require': None,

    'tests_require': '',

    'python_requires': '>3.5.0',

    'entry_points': {
        'steel.commands': [
            'netim = steelscript.netim.commands'
        ]
    },
}


setup(**setup_args)
