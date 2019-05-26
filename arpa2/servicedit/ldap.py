# The default backend for ServiceDIR is LDAP, below.  This makes most
# sense for our initial target of a hosting environment.  It is not
# unthinkable that alternative backends would be created later, such
# as through the configparser module that works on .INI style files.


import weakref

import re

import ldap


varnm_re = re.compile ('^[a-zA-Z0-9_-.]+$')
dnval_re = re.compile ('^[^=,+]+$')

cfgln_re = re.compile ('^([A-Z]+)[ \t]*(.*)$')
whoam_re = re.compile ('^(?:dn: *)?uid=([^=,+]+),associatedDomain=([^=,+]+),.*$')


class ConnectLDAP (object):
    """Connection to LDAP.  
    """

    ldap_conf_file = '/etc/ldap/ldap.conf'

    def load_config (self):
        """Load the configuration in /etc/ldap/ldap.conf as a dictionary
           in the self.ldap_conf variable.
        """
        newcfg = { }
        try:
            for cfgln in open (ldap_conf_file, 'r').readlines ():
                m = cfgln_re.match (cfln)
                if m is not None:
                    (key,val) = m.groups ()
                    newcfg [key] = val
            self.ldap_conf = newcfg
        except:
            sys.stderr.write ('WARNING: Unable to parse ' + ldap_conf_file + '\n')
            pass

    def cfg_uri (self):
        """Retrieve the configured URI for the LDAP server.  This may be
           overridden in environment variable ARPA2_LDAPURI but is normally
           taken from the URI variable in the ldap_conf_file.
        """
        uri = environ.get ('ARPA2_LDAPURI', self.ldap_conf.get ('URI'))
        if uri is None:
            sys.stderr.write ('ERROR: Unable to find ARPA2_LDAPURI envvar or URI in ldap configuration\n')
            sys.exit (1)

    def cfg_binddn (self):
        """Retrieve the user DN as whom to bind/login to LDAP.  This may be
           overridden in environment variable ARPA2_BINDDN but is normally
           taken from the URI variable in the ldap_conf_file.
        """
        binddn = environ.get ('ARPA2_BINDDN', self.ldap_conf.get ('BINDDN'))
        if binddn is not None:
            assert (binddn.endswith (',cn=gssapi,cn=auth'))
        else:
            sys.stderr.write ('INFO: Only capable of ANONYMOUS access to LDAP, set BINDDN for better results\n')
        return binddn

    def login_gssapi (self, binddn):
        """Use GSS-API to login.  There are no provisions for callbacks to
           supply any credentials, because we assume single sign-on as it is
           provided by Kerberos.
        """
        assert (binddn is not None)
        sasl_auth = ldap.sasl.gssapi ()
        self.dap.sasl_interactive_bind_s (binddn, sasl_auth)

    def ldap_whoami (self):
        """Ask LDAP what the authentication / authorised user identity is.
        """
        whoami = dap.whoami_s ()
        m = whoam_re.match (whoami)
        if m is None:
            return None
        else:
            (uid,domain) = m.groups ()
            if '@' in uid:
                return none
            return uid + '@' + domain

    def share_connection (self):
        """Return the contained LDAP connection object for direct access.
           One usage pattern of this class can be to connect and login,
           thereby standardising related resolution matters, and then to
           continue with LDAP using a generic application.  Or mix it.
        """
        return self.dap

    def __init__ (self):
        """Create a new connection based on the setup in /etc/ldap/ldap.conf
           and authenticate using GSS-API with single-signon through Kerberos.
        """
        self.ldap_conf = None
        self.load_config ()
        self.dap = ldap.initialize (self.cfg_uri ())
        #TODO# Learn how to use ANONYMOUS authentication
        self.login_gssapi (self.cfg_binddn ())


class NodeSyncLDAP (dict):
    """Node Sync LDAP objects support the retrieval of attributes
       and sub-nodes.  A Node Sync LDAP object may be present in memory
       before it has been created, or after it has been deleted, to
       collect state while building up a transaction.
    """

    def __init__ (self, topnode, location):
        self.master   = topnode
        self.location = location
        self.vars_one = None
        self.vars_lst = None
        self.children = weakref.WeakValueDictionary ()
        self.loaded  = False
        self.created = None
        self.deleted = False

    def set_variables (self, *singular_vars, list_vars=[]):
        """Set the single-valued variables and list variabels that are of
           interest in this node.  Loading them is deferred to later.
           You must call this operation exactly once.
        """
        assert (self.vars_one is None)
        assert (self.vars_lst is None)
        assert (self.loaded is False)
        for varnm in singular_vars:
            assert (varnm_re.match (varnm))
        for varnm in list_vars:
            assert (varnm_re.match (varnm))
        self.vars_one = singular_vars
        self.vars_lst = list_vars

    def load_vars (self):
        assert (self.loaded is False)
        assert (self.vars_one is not None)
        assert (self.vars_lst is not None)
        #TODO# Load into self.copy_one[] and self.wrap_lst[]

    def get_value (self, varnm, dflt=None):
        """Get the singular value stored under a given varnm.  If it is not
           found, return dflt, which in turn defaults to None.  The value
           itself will be returned.  You can call set_value to update it
           at any time.
        """
        assert (var in self.vars_one)
        if not self.loaded:
            self.load_vars ()
        return self.copy_one [var] or dflt

    def set_value (self, varnm, newval=None):
        """Set the singular value stored in a named variable.  If newval is
           not provided or set to None, then the value will be removed.
           The update will be stored for future processing, during an overall
           synchronisation of transaction state.
        """
        assert (var in self.vars_one)
        if not self.loaded:
            self.load_vars ()
        self.copy_one [var] = newval

    def get_list (self, listnm):
        """Get the list of values stored under the given listnm.  If it is
           not found, an empty list is returned.  The returned list is a
           wrapper that will detect changes as part of an ongoing set of
           changes, which will be deferred until overall synchronisation of
           transaction state.
        """
        assert (var in self.vars_lst)
        if not self.loaded:
            self.load_vars ()
        return self.wrap_one [var]

    def child_location (self, varnm, value):
        """Get a child location under this one, where a given variable name
           and value serve as the key to identify the node.
        """
        #TODO# Escape the variable name and value
        assert (varnm_re.match (varnm))
        assert (dnval_re.match (value))
        return varnm + '=' + value + ',' + self.location

    def child_node (self, varnm, value):
        """Get a child node under this one, where a given variable name and
           value serve as the key to identify the node.
        """
        chiloc = self.child_location (varnm, value)
        obj = self.children.get (chiloc)
        if obj is None:
            obj = NodeSyncLDAP (self.master, self.child_location (varnm, value))
            self.children [varnm + '=' + value] = obj
        return obj

    def children (self, varnm):
        """Get a dictionary of children under this one, each with the given
           variable name and some value.  The dictionary uses the value for
           varnm as its keys and the NodeSyncLDAP as the keyed value.  As
           long as you hold on to this dictionary, or more accurately to its
           entries, you will be holding a copy in memory.  During that time,
           attempts to load the same node as a child of this one return the
           same object thanks to a weakref dictionary in here.  When you
           start changing values the nodes are also kept, pending the end of
           the transaction.
        """
        #TODO# Share weak refs to existing nodes
        #TODO# Load list from LDAP, turn each into NodeSyncLDAP objects
        raise NotImplementedError ()


class ListSync (list):
    """A list that synchronises with some backend, by sending it updates
       to the update_elem() function, which is usually a method bound to
       the sender or a sending context, with a first parameter with the
       list name, and more to go from an old value (or None) to a new
       value (or None).
    """

    def __init__ (self, listname, update_elem):
        self.listname = listname
        self.updater  = update_elem

    def __add__ (self, ys):
        for y in ys:
            self.updater (self.listname, None, y)
        list.__add__ (self, ys)

    def __delslice__ (self, i, j):
        for z in list.__getslice__ (i, j):
            self.updater (self.listname, z, None)
        list.__delslice__ (self, i)

    def __setslice__ (self, i, j, ys):
        for z in list.__getslice__ (i, j):
            self.updater (self.listname, z, y)
        list.__setitem__ (self, i, y)


class SyncLDAP (object):
    """SyncLDAP objects synchronise with LDAP, collecting changes until a
       transaction commits.  At that time, any changes to the LDAP store
       will be made one bit at a time.
       
       This service is implemented with elementary data that assumes a
       link to the stored data.  Specifically, lists and dictionaries
       may be edited as first-class Python objects but they will collect
       LDAP modifications under the hood.  Such changes pile up and form
       a transaction that can be committed (or rolled back) as a whole.
       
       The basic constructs provided here are:
        * lists of objects directly under a given DN
        * lists for attribute values at a given DN
        * dictionaries parsed from lists of attributes at a given DN
        
       SyncLDAP instances are created to maintain one or more of these
       constructs, always specific to a given LDAP connection.
    """

    def __init__ (self, ldapcnx, ispzone, service, userdomain=None):
        """Wrap an LDAP connection to access a given service and optional
           user domain.  You can get and set the user domain at any time,
           but most data access functions assume that one has been setup.
           The service is more like a static given; to switch between those,
           you should create separate objects.
        """
        self.ldapcnx    = ldapcnx
        self.ispzone    = ispzone
        self.service    = service
        self.set_userdomain (userdomain)

    def set_userdomain (self, userdomain):
        self.userdomain = userdomain
        self.basenode = None

    def get_userdomain (self):
        return self.userdomain

    def base_location (self):
        assert (self.userdomain is not None)
        return 'associatedDomain=' + self.userdomain + ',ou=' + self.service + ',o=' + self.ispzone + ',ou=InternetWide'

    def base_node (self, cls=NodeSyncLDAP):
	assert (issubclass (cls, NodeSyncLDAP))
        if self.basenode is None:
            self.basenode = cls (self, self.base_location ())
        return self.basenode
