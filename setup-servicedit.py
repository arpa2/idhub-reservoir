# Lay this egg with "python setup-servicedit.py bdist_egg"

from setuptools import setup

from os import path

#
# Preparation
#
here = path.dirname (path.realpath (__file__))


#
# Packaging Instructions -- arpa2.servicedit
#
readme = open (path.join (here, 'SERVICEDIT.MD')).read ()
setup (

        # What?
        name = 'arpa2-servicedit',
        version = '0.0.0',
        url = 'https://github.com/arpa2/reservoir',
        description = 'ARPA2 ServiceDIT: configuration data structures for InternetWide Architecture',
        long_description = readme,
        long_description_content_type = 'text/markdown',

        # Who?
        author = 'Rick van Rein (for the InternetWide Architecture)',
        author_email = 'rick@openfortress.nl',

        # Where?
        namespace_packages = [ 'arpa2', ],
        packages = [
                'arpa2',
                'arpa2.servicedit',
        ],
        package_dir = {
                'arpa2'            : path.join (here, 'arpa2'),
                'arpa2.servicedit' : path.join (here, 'arpa2', 'servicedit'),
        },

        # How?
        entry_points = {
        },

        # Requirements
        install_requires = [ 'python-ldap', 'six' ],
        extras_require = {
        },
)
