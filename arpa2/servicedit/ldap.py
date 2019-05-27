# The default backend for ServiceDIT is LDAP, below.  This makes most
# sense for our initial target of a hosting environment.  It is not
# unthinkable that alternative backends would be created later, such
# as through the configparser module that works on .INI style files.

# Such choices would presumably be made before deployment time,
# perhaps when selecting what packages to install.  A variant based
# on configparser.ConfigParser could then be a drop-in alternative
# that implements the LDAP model in simpler (and less powerful) code.

# The code below is full of assert() statements, so as to refuse any
# miss-assumptions about how this (fairly abstract) class is meant to
# be used.  Though disruptive, this is intended to give very clear
# guidance to programmers building extensions to this module.  Effort
# went into making the assertion statements readable as repair hints.


import weakref

import re

import ldap


varnm_re = re.compile ('^[a-zA-Z0-9-_.]+$')
dnval_re = re.compile ('^[^=,+]+$')

cfgln_re = re.compile ('^([A-Z]+)[ \t]*(.*)$')
whoam_re = re.compile ('^(?:dn: *)?uid=([^=,+]+),associatedDomain=([^=,+]+),.*$')

# The location of the LDAP user configuration file
#
ldap_conf_file = '/etc/ldap/ldap.conf'


class ConnectLDAP (object):
    """Connection to LDAP.  
    """

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


class AppSyncLDAP (object):
    """AppSyncLDAP objects synchronise with LDAP, and future versions may
       collect changes in transactions.  AppSyncLDAP objects represent an
       LDAP object for a particular application, so they line up with
       a ServiceDIT object
       
       ou=<Application>,o=<ISPzone>,ou=InternetWide
       
       Directly underneath is the level of user domains, and a current
       user domain can be maintained in this object as well as instances
       created for each of those instances.  This results in a base
       location that can be retrieved and for which nodes can be requested.
       
       There can be multiple clients with this same connection at the
       same time, usually caused by separate attempts to operate on the
       same application.  All nodes underneath this one would normally
       be DataSyncLDAP instances, but probably as a subclass thereof.
       In fact, AppSyncLDAP is commonly subclassed by applications too.
    """

    def __init__ (self, ldapcnx, ispzone, service, basenodecls, userdomain=None):
        """Wrap an LDAP connection to access a given service and optional
           user domain.  You can get and set the user domain at any time,
           but most data access functions assume that one has been setup.
           The service is more like a static given; to switch between those,
           you should create separate objects.
           The base node class is the Python class that will be instantiated
           to represent nodes for individual user domains.
        """
        assert (isinstance (basenode, cls))
        self.ldapcnx = ldapcnx
        self.ispzone = ispzone
        self.service = service
        self.dom2obj = weakref.WeakValueDictionary ()
        self.basecls = basenodecls
        self.set_userdomain (userdomain)

    def set_userdomain (self, userdomain=None):
        """Change what is used as the current user domain.
           In spite of the dynamicity that this allows, child nodes that
           were created for one user domain will continue to be shared
           as long as the old uses exist.
           
           When None is provided for the user domain, it will be removed
           and not all functions will work.
        """
        self.userdomain = userdomain

    def get_userdomain (self):
        """Retrieve the currently used user domain.  This may be None
           if no user domain is currently setup.
        """
        return self.userdomain

    def base_location (self):
        """Return the node in the ServiceDIT representing the current domain
           for the application setup when this object was initialised.
        """
        assert (self.userdomain is not None)
        return 'associatedDomain=' + self.userdomain + ',ou=' + self.service + ',o=' + self.ispzone + ',ou=InternetWide'

    def base_node (self):
        """Return a Python object that references the ServiceDIT and share
           it with any other objects currently active for the same node and
           requested through this same AppSyncLDAP instance.  The object made
           is an instance of the basenodecls that was provided during this
           AppSyncLDAP initialisation.
        """
        assert (self.userdomain is not None)
        basenode = self.dom2obj.get (self.userdomain, None)
        if basenode is None:
            basenode = self.basecls (self, self.base_location ())
            self.dom2obj [self.userdomain] = basenode
        return basenode

    def resource_class (self):
        """By default, AppSyncLDAP is not a resource class in ACL terms,
           but this may be overridden in an application-specific subclass.
           It should then return a lowercase UUID string that was fixed
           for this application.
        """
        return None

    def resource_instance (self):
        """AppSyncLDAP sits too high up the ServiceDIT to ever be a resource
           instance in ACL terms.  It should never return a key from this
           function, and subclasses should not override this either.
        """
        raise Exception ('AppSyncLDAP objects cannot be ACL resource instance')


class DataSyncLDAP (dict):
    """Node Sync LDAP objects support the retrieval of attributes
       and sub-nodes.  A Node Sync LDAP object may be present in memory
       before it has been created, or after it has been deleted.
       
       These objects can change attribute values, search for children,
       and deliver new objects as application class instances, while
       sharing them if an object is currently in use somewhere else.
       
       The current implementation simply acts on LDAP directly, but
       future versions are expected to collect changes and commit
       them in transactions.
    """

    def __init__ (self, topnode, location):
        self.master   = topnode
        self.location = location
        self.atnm_one = None
        self.atnm_lst = None
        self.attrvals = { }
        self.children = weakref.WeakValueDictionary ()
        self.loaded  = False
        self.created = False

    def set_variables (self, singular_attrs=[], list_attrs=[]):
        """Set the single-valued variables and list variabels that are of
           interest in this node.  Loading them is deferred to later.
           You must call this operation exactly once.  This is mostly done
           immediately after initialisation.  Most probably, it would be
           called from a subclass's initialisation, where the desired
           knowledge is available.
        """
        assert (self.atnm_one is None)
        assert (self.atnm_lst is None)
        assert (not self.loaded)
        for varnm in singular_attrs:
            assert (varnm_re.match (varnm))
        for varnm in list_attrs:
            assert (varnm_re.match (varnm))
        self.atnm_one = singular_attrs
        self.atnm_lst = list_attrs

    def create (self, classes, attrs_dict):
        """After preparing with set_variables, create a classes instance
           with attributes from atnm_dict.  For list_vars, an iteratable
           is expected to reveal all the attribute values.  Variables
           not set during creation will not be created at all; there are
           no default values but absense.
           
           This will also make calls to the methods resource_class()
           and resource_instance() to see if these have been overridden
           to supply additional information, which will then be added.
        """
        assert (not self.created)
        assert (self.atnm_one is not None)
        assert (self.atnm_lst is not None)
        assert (self.loaded is False)
        if isinstance (classes, str):
            classes = [classes]
        self.attrvals ['objectClass'] = classes [:]
        rescls = self.resource_class ()
        if rescls is not None:
            self.attrvals ['resourceClassUUID'] = rescls
            self.attrvals ['objectClass'].append ('resourceClassObject')
        resins = self.resource_insance ()
        if resins is not None:
            self.attrvals ['resourceInstanceKey'] = resins
            self.attrvals ['objectClass'].append ('resourceInstanceObject')
        for (k,v) in atnm_dict.items ():
            if k in self.atnm_one:
                self.attrvals = v
            elif k in self.atnm_lst:
                self.attrvals = v [:]
            else:
                raise Exception ('Attribute %r unknown' % k)
        self.ldapcnx.dap.add_s (self.location, self.attrvals)
        self.created = True

    def delete (self):
        """Remove this object from LDAP.  It must exist, but need not have
           had the create() or load_vars() methods invoked on it.  Having
           said this, attempts to remove an object that does not exist in
           LDAP will raise an exception.  The same is likely when children
           of this node are present in storage.  When this call succeeds,
           its attributes will have been reset and so it _may_ be recycled.
        """
        self.ldapcnx.dap.delete_s (self.location)
        self.created = False
        self.loaded  = False
        self.attrvals = { }

    def load_vars (self, classes, filterstr=None):
        """Load the variabels as they are currently stored in LDAP.
           This should be called after initialisation, for objects
           that are not created from scratch.  Call set_variables
           first, so that it is known what variables are of interest
           in this place.
        """
        assert (not self.loaded)
        assert (not self.created)
        assert (self.atnm_one is not None)
        assert (self.atnm_lst is not None)
        atlist = self.atnm_one + self.atnm_lst
        classflt = '(&' + ''.join (
                    [ '(objectClass=' + cls + ')' for cls in classes]
                    ) + ')'
        print ('DEBUG: classflt', classflt)
        if filterstr is not None:
            combiflt = '(&' + classflt + filterstr + ')'
        else:
            combiflt = classflt
        print ('DEBUG: combiflt', combiflt)
        qr = self.ldapcnx.dap.search_s (self.location,
                    ldap.SCOPE_BASE,
                    filterstr=combiflt,
                    attrlist=atlist)
        print ('DEBUG: Query Result: %r' % qr)
        [(_dn,entry)] = qr
        for atnm in atnm_lst:
            self.attrvals [atnm] = entry.get (atnm, [])
        for atnm in atnm_one:
            self.attrvals [atnm] = entry.get (atnm, [None]) [0]
        self.loaded = True

    def get_value (self, varnm, dflt=None):
        """Get the singular value stored under a given varnm.  If it is not
           found, return dflt, which in turn defaults to None.  The value
           itself will be returned.  You can call set_value to update it
           at any time.
        """
        assert (var in self.atnm_one)
        if not self.loaded:
            self.load_vars ()
        return self.attrvals [var] or dflt

    def set_value (self, varnm, newval=None):
        """Set the singular value stored in a named variable.  If newval is
           not provided or set to None, then the value will be removed.
           The update will be stored for future processing, during an overall
           synchronisation of transaction state.
        """
        changes = [ ]
        assert (varnm in self.atnm_one)
        if not self.loaded:
            self.load_vars ()
        oldval = self.attrvals [varnm]
        if oldval [varnm] is not None:
            changes.append ( (ldap.MOD_DELETE, self.location, oldval) )
        self.attrvals [varnm] = newval
        if newval is not None:
            changes.append ( (ldap.MOD_ADD,    self.location, newval) )
        self.ldapcnx.dap.modify_s (self.location, changes)

    def get_list (self, listnm):
        """Get the list of values stored under the given listnm.  If it is
           not found, an empty list is returned.  Call set_list_elem() to
           update a stored value at any time.  The list holds attributes,
           which are not wrapped in an application-specific class.
        """
        assert (var in self.atnm_lst)
        if not self.loaded:
            self.load_vars ()
        return self.wrap_one [var]

    def set_list_elem (self, listnm, oldval, newval):
        """Set a list element value from oldval to newval.  Either of these
           values can be None to indicate absense, so this function can
           also be used to add and remove values in the list.
           
           Future spin-off functions may automatically respond to returned
           lists by invoking this function, or a similar one, when a list
           is edited.  By that time, this method name will be stripped from
           any effect and its use will be deprecated or rejected.
        """
        changes = [ ]
        if oldval is not None:
            del self.attrvals [listnm] [oldval]
            changes.append ( (ldap.MOD_DELETE, listnm, oldval) )
        if newval is not None:
            self.attrvals [listnm].append (newval)
            changes.append ( (ldap.MOD_ADD,    listnm, newval) )
        self.ldapcnx.dap.modify_s (self.location, changes)

    def child_location (self, varnm, value):
        """Get a child location under this one, where a given variable name
           and value serve as the key to identify the node.
        """
        #TODO# Escape the variable name and value
        assert (varnm_re.match (varnm))
        assert (dnval_re.match (value))
        return varnm + '=' + value + ',' + self.location

    def child_node (self, varnm, value, cls=None):
        """Get a child node under this one, where a given variable name and
           value serve as the key to identify the node.
           The child node instantiates as an instance of cls, which defaults
           to DataSyncLDAP.
        """
        assert (varnm_re.match (varnm))
        assert (dnval_re.match (value))
        if cls is None:
            cls = DataSyncLDAP
        else:
            assert (issubclass (cls, DataSyncLDAP))
        chiloc = self.child_location (varnm, value)
        obj = self.children.get (chiloc, None)
        if obj is None:
            obj = cls (self.master, self.child_location (varnm, value))
            self.children [varnm + '=' + value] = obj
        else:
            assert (isinstance (obj, cls))
        return obj

    def children (self, varnm, cls=None, classes=[], filterstr=None):
        """Get a dictionary of children under this one, each with the given
           variable name and some value.  The dictionary uses the value for
           varnm as its keys and instantiates cls for the keyed value.  As
           long as you hold on to this dictionary, or more accurately to its
           entries, you will be holding a copy in memory.  During that time,
           attempts to load the same node as a child of this one return the
           same object thanks to a weakref dictionary in here.  When you
           start changing values the nodes are also kept, pending the end of
           the transaction.
           Child nodes instantiate as instances of cls, which defaults to
           DataSyncLDAP.
        """
        assert (varnm_re.match (varnm))
        if cls is None:
            cls = DataSyncLDAP
        else:
            assert (issubclass (cls, DataSyncLDAP))
        if isinstance (classes, str):
            classes = [classes]
        classflt = '(&' + ''.join (
                    [ '(objectClass=' + cls + ')' for cls in classes]
                    ) + ')'
        print ('DEBUG: classflt', classflt)
        varnmflt = '(' + varnm  + '=*)'
        print ('DEBUG: varnmflt', varnmflt)
        combiflt = '(&' + classflt + varnmflt + (filterstr or '') + ')'
        print ('DEBUG: combiflt', combiflt)
        qr = self.ldapcnx.dap.search_s (self.location,
                ldap.SCOPE_ONE,
                attrlist=[varnm],
                filterstr=combiflt)
        print ('DEBUG: Query Result: %r' % qr)
        retval = { }
        for (dn, entry) in qr.items ():
            var_is_val = dn.split (',') [0]
            obj = self.children.get (var_is_val, None)
            if obj is None:
                obj = cls (self.master, dn)
                self.children [var_is_val] = obj
            else:
                assert (isinstance (obj, cls))
            for val in entry.get (varnm, []):
                retval [val] = obj
        return retval

    def resource_class (self):
        """By default, DataSyncLDAP is not a resource class in ACL terms,
           but this may be overridden in an application-specific subclass.
           It should then return a lowercase UUID string that was fixed
           for this application.
        """
        return None

    def resource_instance (self):
        """By default, DataSyncLDAP is not a resource instance in ACL terms,
           but this may be overridden in an application-specific subclass.
           It should then return the string notation that serves as the key
           for the applicable resource class.
        """
        return None
