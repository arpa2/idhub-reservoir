
import re
import uuid

from weakref import WeakValueDictionary

from .reservoir import SyncLDAP


zone_re = re.compile ('^[-a-zA-Z0-9]+(\.[-a-zA-Z0-9]+){1,}$')
user_re = re.compile ('^[a-zA-Z0-9-+]+$')
step_re = re.compile ('^[ -~]+$')
uuid_re = re.compile ('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


class Reservoir (WeakValueDictionary):
    """Reservoir objects represent a link to the LDAP repository and
       its backends.  The connection is specific for an ISP (identified
       by their domain name) and a user's domain.  This culminates into
       a baseDN over an LDAP connection -- or more generally, into a
       location at a backend.

       Reservoir objects also concentrate a dictionary to lookup a DN
       and map it to an object.  This is available through regular
       dictionary functions.  Usually, entries are added automatically
       when their corresponding objects are created.  They are weakly
       referenced, so they will implicitly be removed when their objects
       are no longer held by anyone.
       
       Reservoir objects also contain a transaction context.  When any
       object is loaded from LDAP, its storage changes will be collected
       and applied during sync().  While the transaction is in progress,
       strong references to these objects are kept.  The methods to use
       are txn_commit() and txn_rollback().  There is no need to start
       transactions explicitly.
    """

    def __init__ (self, ldapcnx, isp_domain, usr_domain, username=None):
        assert (zone_re.match (isp_domain))
        assert (zone_re.match (usr_domain))
        assert (user_re.match (username  ))
        self.isp     = ispdomain
        self.domain  = usrdomain
        self.uid     = username
        self.ldapcnx = ldapcnx
        self.baseDN  = 'associatedDomain=' + domain + ',ou=Reservoir,o=' + isp + ',ou=InternetWide'

    def home_dn (self):
        """Return the home DN for this Reservoir.  When a username was
           given, this produces the starting DN for the user.  If not,
           it produces the starting DN for the user domain.
        """
        if not self.uid:
            dn = self.baseDN
        else:
            dn = 'uid=' + self.uid + ','  + self.baseDN

    def home (self):
        """Return the Index node for this Reservoir.  When a username was
           given, this produces the starting Index for the user.  If not,
           it produces the starting Index for the user domain.
           
           Note that the returned object is an Index, not a Collection.
           In other words, it can be used to start traversing names, but
           it does not have Resource entries.
        """
        dn = self.home_dn ()
        return Index (self, self.baseDN)

    def collection_dn (self, coll_uuid):
        """Return the DN for a given lowercase UUID representing a
           Resource Collection in this Reservoir.
        """
        assert (uuid_re.match (coll_uuid))
        return 'resins=' + coll_uuid + ',' + self.baseDN

    def collection (self, coll_uuid):
        """Return the Collection for a given lowercase UUID representing
           a Resource Collection in this Reservoir.
        """
        dn = self.collection_dn (coll_uuid)
        coll = self.get (dn) or Collection (self, dn, coll_uuid)
        assert (isinstance (coll, Collection))
        return coll

    def resource_dn (self, coll_uuid, res_name):
        """Return the DN for a given lowercase UUID and the resource
           name, together representing a Resource in this Reservoir.
        """
        assert (step_re.match (res_name))
        return 'resource=' + res_name + self.collection_dn (coll_uuid)

    def resource (self, coll_uuid, res_name):
        """Return the Resource for a given lowercase UUID and the
           resource name, together representing a Resource in this
           Reservoir.
        """
        dn = self.resource_dn (coll_uuid, res_name)
        res = self.get (dn) or Resource (self, dn, coll_uuid, res_name)
        assert (isinstance (res, Resource))
        return res

    def make_uuid (self):
        """Generate a random UUID and return it as a str value.
           
           There is no certainty that the UUID is new.  The
           only of knowing this for certain is to create an
           LDAP object with it and see if it complains.
        """
        return str (uuid.uuid4 ())

    def txn_add (self, object_dn, to_be_synced):
        """Add an object to those that will receive sync() when
           the transaction is committed.  This causes a strong
           reference to be stored to that object.
           
           Every added object must support a clear_cache() and
           sync_cache() method, which must have a reverse flag.
           Clearing caches triggers reloads if the content is
           addressed again later, and cache synchronisation is
           used to save data into LDAP.  The reverse operation
           is easily available in LDAP, and can be used to have
           some mechanism to reverse sequences of atomic changes
           if they fail halfway.
        """
        if not to_be_synced in self.txnobjs:
                self.txnobjs.append (to_be_synced)

    def txn_abort (self):
        """Abort the current transaction.  This drops all
           strong references to in-memory changes.  Clear
           the cached state of each of these objects.
        """
        for obj in self.txnobjs:
            obj.clear_cache ()
        self.txnobjs = []

    def txn_commit (self):
        """Commit the current transaction.  This saves all
           changes to LDAP.  Caches are cleared so as to
           allow reloading of state after possible changes
           by other transactions.
        """
        all_ok = False
        txnobjs = self.txnobjs
        self.txnobjs = None
        idx = 0
        try:
            for idx in range (len (txnobjs)):
                txnobjs [idx].sync_cache ():
            all_ok = True
        except:
            # turn back: for revidx in [idx-1,idx-2,...,0]
            for revidx in range (idx-1,-1,-1):
                txnobjs [idx].sync_cache (reverse=True)
            self.txn_rollback ()
            return False
        for obj in txnobjs:
            obj.clear_cache ()
        self.txnobjs = []
        return True


class Index (dict):
    """Indexes represent a name-to-Collection mapping in Reservoir.
       The most important method defined here is walk, which makes
       one or more steps from the Index to return the new Index
       object.
       
       Indexes are also the home to management commands; for instance,
       the change or removal of a name or the creation of a new one
       pointing to any given Collection.
       
       Index objects map names to lowercase UUID strings as found
       in LDAP.  The values are loaded upon creation, but they may
       also be set by calling programs.
    """

    def __init__ (self, resv, dn):
        """Return an Index object for the given DN.
        """
        self.resv = resv
        self.dn   = dn
        self.index = None
        self.load_index ()

    def clear_cache (self):
        """Drop the Index's list of Collection names.
        """
        self.index = None

    def sync_cache (self, reverse=False):
        """Store any cached changes to LDAP.  Do not forget the
           changes that are being made, because they may have to
           be reversed if another object in this transaction fails
           and transaction semantics requires the reversal of any
           preceding LDAP updates in the same transaction.
        """
        pass  #TODO#IMPLEMENT#

    def load_index (self):
        """Load the Index entries from LDAP.  This can be called
           again to reload it at any later time.
           #TODO# Unpack the "UUID SPACE NAME" format to a dict.
        """
        self.index = resv.store.attr_list (self.dn, 'reservoirIndex', 'reservoirRef')
        self.resv.txn_add (self.dn, self)

    def list_index (self):
        """Return the Index entries as a dictionary.  This can be
           edited, and the updates will be synchronised in LDAP.
        """
        if self.index is None:
            self.load_index ()
        return self.index

    def collection (self, coll_name):
        """Return the Collection object underneath this one,
           as indicated by its name.
        """
        assert (step_name.match (coll_name))
        coll_uuid = self.index [coll_name]
        return self.resv.collection (self, coll_uuid)

    def walk (self, path, res_name=None, maybe_res=False):
        """Walk down a path from the current Index, and return the
           Collection at the end node.  The path is either a list
           of index names or a single index name as a str value.
           
           Normally, the Index is actually a Collection.  The
           only situation where it is just an Index is if the
           path is empty and the current object is an Index.
           
           If res_name is set, it will be interpreted as the
           name of a Resource to find at the end of the path.
           This means that another kind of object is returned.
           
           When maybe_res is True, the returned object can be
           either.  If a full path to an Index exists, then
           the return value is an Index.  Only when the last
           element on the path does not exist and maybe_res is
           True is an attempt made to interpret the last path
           element like res_name.
           
           It is possible that a requested path does not exist.
           In that case, None is returned instead of the
           requested object.  TODO: Raise exception?
        """
        if type (path) == str:
            path = [path]
        #
        # Only keep res_name if it makes sense
        if res_name is not None or len (path) == 0:
            maybe_res = False
        #
        # Iterate over path elements to find Index objects
        prev = None
        here = self
        for step in path:
            # Syntax check
            assert (step_re.match (step))
            # A name was not found and it was not the last
            if here is None:
                return None
            # Lookup the next item
            prev = here
            coll_uuid = here.get (step)
            if coll_uuid is not None:
                here = self.resv.collection (coll_uuid)
            else:
                here = None
        #
        # See if the last path element could be res_name
        if here is None:
            if maybe_res:
                res_name = path [-1]
                here = prev
            else:
                return None
        #
        # Try to find the res_nane and return a Resource
        if res_name is not None:
            here = self.resv.resource (coll_uuid, res_name)
        #
        # Now, here is either a Collection or a Resource
        # as determined by the parameters provided
        return here


class Collection (Index):
    """Collections are nodes in the LDAP tree of Reservoir that
       represent an Index with names pointing to other Collection
       objects, as well as resource names that would end a walk
       to a Resource.
       
       Most Index objects are also Collections.  The exceptions
       are those LDAP nodes that start pointing to Reservoir
       nodes.  Domains, users and services can all have Indexes
       that are not Collections added to their LDAP objects.
    """

    def __init__ (self, resv, dn, coll_uuid):
        Collection.__init__ (self, resv, dn)
        self.uuid = coll_uuid
        self.resources = None
        self.created = False
        self.deleted = False

    def create (self):
        """Indicate that this object does not yet exist in LDAP,
           and would be created as a new instance as part of the
           current transaction.
        """
        self.created = True

    def delete (self):
        """Indicate that this object should be taken out of LDAP,
           at least at the end of the current transaction.
        """
        self.deleted = True

    def clear_cache (self):
        """Drop the Collection's list of Resource names and the Index's
           list of Collection names.
        """
        Collection.clear_cache (self)
        self.resources = None

    def sync_cache (self):
        """Store any cached changes to LDAP.
        """
        pass  #TODO#IMPLEMENT#

    def load_resources (self):
        """Load the list of Resource names currently found in
           LDAP under this Collection.
        """
        self.resources = resv.store.child_list (self.dn, 'reservoirResource', 'resource')
        self.resv.txn_add (self.dn, self);

    def list_resources (self):
        """Return a list of Resource names in this Collection.
           Resolving these names to a Resource object can be
           done with the resource() method.  Changes to
           this list are synchronised to LDAP.
        """
        if self.resources is None:
            self.load_resources ()
        return self.resources

    def resource (self, res_name):
        """Return a Resource by name, as it is defined in this
           Collection.
        """
        return self.resv.resource (self.uuid, res_name)


class Resource (object):
    """Resources are nodes in the LDAP tree of Reservoir that
       represent files and their metadata.  The actual contents
       may be downloaded, but operations exist for scuh things
       as hashing, publishing, and removing the Resource from
       the Reservoir.
    """

    def __init__ (self, resv, coll_uuid, res_name):
        """Describe a node of Reservoir in memory.  This may be
           out of sync with the data in LDAP, for instance while
           building it or after deleting it.
        """
        self.resv = resv
        self.coll = coll_uuid
        self.name = res_name
        self.created = False
        self.deleted = False

    def create (self):
        """Indicate that this Resource does not yet exist in LDAP,
           and would be created as a new instance as part of the
           current transaction.
        """
        self.created = True

    def delete (self):
        """Indicate that this Resource should be taken out of LDAP,
           at least at the end of the current transaction.
        """
        self.deleted = True

