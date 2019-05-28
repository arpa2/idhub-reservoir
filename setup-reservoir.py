# Lay this egg with "python setup-reservoir.py bdist_egg"

from setuptools import setup

from os import path

#
# Preparation
#
here = path.dirname (path.realpath (__file__))


#
# Packaging Instructions -- arpa2.reservoir
#
readme = open (path.join (here, 'RESERVOIR.MD')).read ()
setup (

        # What?
        name = 'arpa2-reservoir',
        version = '0.0.0',
        url = 'https://github.com/arpa2/reservoir',
        description = 'ARPA2 Reservoir: object store with meta-data in LDAP',
        long_description = readme,
        long_description_content_type = 'text/markdown',

        # Who?
        author = 'Rick van Rein (for the ARPA2 Reservoir project)',
        author_email = 'rick@openfortress.nl',

        # Where?
        namespace_packages = [ 'arpa2', ],
        packages = [
                'arpa2',
                'arpa2.reservoir',
        ],
        package_dir = {
                'arpa2'           : path.join (here, 'arpa2'),
                'arpa2.reservoir' : path.join (here, 'arpa2', 'reservoir'),
        },

        # How?
        entry_points = {
        },

        # Requirements
        install_requires = [ 'python-ldap', 'six', 'arpa2-servicedit' ],
        extras_require = {
                'Riak KV' : [ 'riakkv' ],
        },
)
