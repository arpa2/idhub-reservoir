import weakref

import re
import uuid

from arpa2.servicedit import AppSyncLDAP, DataSyncLDAP


acl_resource_class = '904dfdb5-6b34-3818-b580-b9a0b4f7e7a9'


zone_re = re.compile ('^[-a-zA-Z0-9]+(\.[-a-zA-Z0-9]+){1,}$')
user_re = re.compile ('^[a-zA-Z0-9-+]+$')
step_re = re.compile ('^[ -~]+$')
uuid_re = re.compile ('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
idxe_re = re.compile ('^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?: ([ -~]+))?$')
cldn_re = re.compile ('^resins=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}),associatedDomain=')
rsdn_re = re.compile ('^documentIdentifier=([^,]+),resins=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}),associatedDomain=')


class Reservoir (AppSyncLDAP):
    """Construct an application node to represent the complete Reservoir
       application, with all its instances.  This class starts a cache
       for already-loaded objects, so it is advisable to have one such
       class per application.  Except of course, when application logic
       dictates their separation, for instance to isolate user sessions.
       
       From this node, one should go down by choosing a user domain.  An
       initial choice may already be made, and the current one may also
       be changed at any time.  Caches will share these nodes through the
       Python weak reference concept -- keep pointing to an object for as
       long as you would like to share it, and feel free to use the
       ServiceDIT as a means of indexing it.
    """
    def __init__ (self, ldapcnx, userdomain=None):
        AppSyncLDAP.__init__ (self, 'arpa2.net', 'Reservoir', Domain, userdomain=None)


class Index (DataSyncLDAP):
    """Indexes represent a name-to-Collection mapping in Reservoir.
       
       Indexes occur in a number of places, namely as default starting
       points for a Domain (the associatedDomain= on top) as well as
       for Users (in their uid=,ou=Users,associatedDomain=) and every
       Collection (resins=,associatedDomain=).

       Because Collections are always Indexes, it is possible to walk
       a path to an eventual Resource, even if the structure of the
       stored data in LDAP has a flatter structure.
       
       Indexes are also the home to many user-issued management commands;
       for instance, the change or removal of a name or the creation of a
       new use of the Reservoir points to any given Collection.
       
       Index objects map names to lowercase UUID strings as found
       in LDAP.  One name is special and serves as a default, and that
       is the absent name.  In terms of storage in the ServiceDIT, an
       Index is represented as collectionRef entries that hold a UUID
       in lowercase textual form which in all cases but the default is
       followed by a single space and the name for the Index entry.
    """

    def __init__ (self, resv, parent, dn):
        """Return an Index object for the given DN.
        """
        assert (isinstance (resv, Reservoir))
        DataSyncLDAP (self, resv, parent, dn)
        self.add_structure (classes=set (['resourceIndex']),
                            multiple_attrs=['collectionRef', 'reservoirRemoteRef'],
                            singular_attrs=['resins'])
        self.uuid = None
        self.index = None

    def resource_class (self):
        """Indexes return the resource class fixated for Reservoir.
           Resource instances however, are only shown in Collection objects.
        """
        return '904dfdb5-6b34-3818-b580-b9a0b4f7e7a9'

    def load_index (self):
        """Load the Index from LDAP.  This involves fetching
           its attributes from the storage backend.  Call this
           operation just once, and not for a created index.
        """
        assert (self.index is None)
        assert (self.uuid is None)
        self.get_vars ()
        #TODO# Future support should add reservoirRemoteRef
        self.index = { }
        for idxentry in self.get_list ('collectionRef'):
            idxentry_match = idxe_re.match (idxentry)
            assert (idxentry_match is not None)
            (uuid,name) = idxentry_match.groups ()
            self [name] = uuid

    def create_index (self):
        """Create an Index from scratch.  This involves the
           construction of a fresh UUID for the entry, to be
           used for ACL management.
        """
        assert (self.uuid is None)
        self.uuid = str (uuid.uuid4 ())
        self.index = { }

    def index (self):
        """Return the Index entries as a dictionary.  This can be
           edited, and the updates will be synchronised in LDAP.
        """
        if self.index is None:
            self.load_index ()
        return self.index

    def get_index_entry (self, name, dflt=None):
        """Return the UUID for the given name in this index.
           If it is absent, dflt will be returned instead,
           or None if this is not specified.
        """
        if self.index is None:
            self.load_index ()
        return self.index.get (name, dflt)

    def set_index_entry (self, name, uuid):
        """Update an index entry to point to the given UUID value.
           If the UUID is None, the entry should be removed.
           The value None for name indicates the default entry.
        """
        assert (uuid_re.match (uuid))
        assert (name is None or step_re.match (name))
        # Load the entry on first contact
        if self.index is None:
            self.load_index ()
        # Find value for oldattr
        if name in self.index:
            if name is not None:
                oldattr = '%s %s' % (uuid, self.index [name])
            else:
                oldattr = uuid
        else:
            oldattr = None
        # Find value for newattr
        if name is not None:
            newattr = '%s %s' % (uuid, name)
        else:
            newattr = uuid
        # Update LDAP from oldattr to newattr
        self.set_list_elem ('collectionRef', oldattr, newattr)
        # Update the index as cached in self
        if uuid is not None:
            self.index [name] = uuid
        else:
            del self.index [name]

    def collection (self, coll_name):
        """Return the Collection object underneath this one,
           as indicated by its name.  Set coll_name to None
           to retrieve the default entry of this Index.
        """
        if self.index is None:
            self.load_index ()
        assert (coll_name is None or step_re.match (coll_name))
        coll_uuid = self.index [coll_name]
        return self.appinst.collection (self, coll_uuid)

    def walk (self, path, res_name=None, maybe_res=False):
        """Walk down a path from the current Index, and return the
           Collection at the end node.  The path is either a list
           of index names or a single index name as a str value.
           
           Often, the Index returned is also a Collection.  The
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
        if isinstance (path, str):
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
            coll_uuid = here.get_index_entry (step)
            if coll_uuid is not None:
                here = self.appinst.collection (coll_uuid)
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
            here = self.appinst.resource (coll_uuid, res_name)
        #
        # Now, here is either a Collection or a Resource
        # as determined by the parameters provided
        return here


class Domain (Index):
    """Domain objects represent a link to the ServiceDIT and its LDAP or
       other backend.  The connection is specific for a user's domain.
       
       The Domain object is the place to ask for a Collection by UUID,
       and possibly a Resource by Collection UUID and Resource Name.
       
       Several Indexes that can be reached from the Domain object; it is
       one itself, serving as the user domain's "home" index.  Similarly,
       it can be asked for the "home" of a user, for which it locates
       another object below this one, at uid=,ou=Users.  Finally, every
       Collection that it can lookup is an Index.
       
       Future versions may use the Domain as a point for collecting the
       changes that form a transaction, and for committing it or rolling
       it back.
    """

    def __init__ (self, app_resv, parent, location):
        assert (isinstance (app_resv, Reservoir))
        assert (parent == app_resv)
        Index.__init__ (self, app_resv, parent, location)
        self.baseDN  = location
        self.users   = None

    def _have_users_node (self):
        if self.users is None:
            #TODO# May need to create this node if it does not exist
            self.users = self.child_node ('ou', 'Users')
        return self.users

    def home_dn (self, username=None):
        """Return the home DN for this Reservoir.  When a username is
           given, this produces the starting DN for the user.  If not,
           it produces the starting DN for the user domain (which is
           just this object itself).
        """
        if username is None:
            dn = self.baseDN
        else:
            assert (user_re.match (username))
            dn = 'uid=' + self.uid + ',ou=Users,'  + self.baseDN

    def home (self, username=None):
        """Return the Index node for this Reservoir.  When a username is
           given, this produces the starting Index for the user.  If not,
           it produces the starting Index for the domain (which is just
           this object itself).
           
           Note that the returned object is an Index, not a Collection.
           In other words, it can be used to start traversing names, but
           it does not have Resource entries.
        """
        if username is None:
            return self
        else:
            assert (user_re.match (username))
            users = self._have_users_node ()
            return self.child_node ('uid', username, DomainUser)

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
        assert (uuid_re.match (coll_uuid))
        return self.child_node ('resins', coll_uuid, Collection)

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
        coll = self.collection (coll_uuid)
        #TODO# Maybe reference the Collection from the Resource?
        return self.child_node ('cn', res_name, Resource)


class DomainUser (DataSyncLDAP):
    """DomainUser objects represent uid=,ou=Users,associatedDomain= objects
       in the subtree for the Reservoir application.  This is used for both
       users and services, along with all variations that each can have.
       
       Every DomainUser can have an Index, though it may be empty.  The
       customary absense-of-name indicates a default entry that can be
       requested when no name is provided.
    """

    def __init__ (self, resv, parent, dn):
        assert (isinstance (resv, Reservoir))
        assert (isinstance (parent.parent (), Domain))
        DataSyncLDAP.__init__ (self, resv, parent, dn)
        self.add_structure (classes=['uidObject'],
                            singular_attrs=['uid'])


class Collection (Index):
    """Collections are nodes in the LDAP tree of Reservoir that
       represent an Index with names pointing to other Collection
       objects, as well as resource names that would end a walk
       to a Resource.
       
       The location of a Collection has a flat organisation, namely
       at resins=<coll_uuid>,associatedDomain= in the Reservoir
       subtree of the ServiceDIT.  ACL settings are made for each
       Collection separately, and it is the last Collection in a
       potential path that matters, thus making sense of this flat
       structure and allowing the direct access to a Collection by
       its UUID.  As a result of this, Collection objects must have
       LDAP objectClass resourceInstanceObject, and because of that
       they must have resourceClass and resourceInstance attributes.
       We shall in fact use the latter as a `resins=` RDN, so any
       objects underneath can deduce the applicable ACL from the DN
       alone -- this applies to the Resource objects defined below.
       
       Most Index objects are also Collections.  The exceptions
       are those LDAP nodes that start pointing to Reservoir
       nodes.  Domains, users and services can all have Indexes
       that are not Collections added to their LDAP objects.
    """

    def __init__ (self, resv, parent, dn):
        assert (isinstance (resv, Reservoir))
        assert (isinstance (parent, Domain))
        dn_proper_for_collection = cldn_re.match (dn)
        assert (dn_proper_for_collection)
        coll_uuid = dn_proper_for_collection.group (1)
        DataSyncLDAP.__init__ (self, resv, parent, dn)
        self.add_structure (classes=['reservoirCollection'],
                            singular_attrs=['resins'],
                            multiple_attrs=['cn', 'description'])
        self.uuid = coll_uuid

    def resource_instance (self):
        """Return the ACL resource instance as a lowercase UUID
           with the resins value in the RDN for this Collection.
        """
        return self.uuid

    def resource_dn (self, docid):
        """Return a DN for a reservoir Resource object under the
           given document identifier.
        """
        return self.child_dn ('documentIdentifier', docid)

    def resource (self, docid):
        """Return a reservoir Resource object for the given
           document identifier.
        """
        return self.child ('documentIdentifer', docid, Resource)

    def search (self, filterstr=None):
        """Return a dictionary of Resource objects under this
           Collection object.  The objects may not have been
           loaded yet, but their document identifiers are as
           in storage.  This is a moderately expensive function,
           so that it is advantageous to cache whenever possible.
           
           The optional filterstr can be used to select certain
           content only, which defaults to listing all nodes.
        """
        return self.children ('documentIdentifier',
                            cls=Resource,
                            classes=['reservoirResource'],
                            filterstr=filterstr)

    def access_description (self, flags='v', combinator=' and '):
        """Given a string of access flags, describe its access level.
           The flags should be an iterable set of characters, such as
           a set, list or string.
        """
        if flags == '':
            return 'No access rights at all'
        flags2descr = {
            'a': 'administration',
            's': 'service access',
            'd': 'resource deletion',
            'c': 'resource creation',
            'w': 'writing',
            'r': 'reading',
            'p': 'proving without seeing',
            'k': 'knowing about existence',
            'o': 'owning',
            'v': 'visiting',
        }
        return combinator.join ([flag2descr [f] for f in flags])

    def access_rights (self):
        """Return the string with access rights characters that
           define what the current user may do to Collections and
           its contained Resources.  This knowledge will be cached
           in this Collection object to allow fast access through
           the self.parent() reference from any Resource.
           The return value is a string, which allows iteration
           over its characters.
        """
        #TODO# Implement
        return 'dcwrpkov'

    def access_require (self, flags='v'):
        """Ensure that the requested access rights are present in
           the access_rights() string.  This is a quick way for
           anyone to check that a set of desired flags are all
           available.  If not, a clear exception is raised.
           The flags should be an iterable set of characters, such
           as a set, list or string.
        """
        right = self.access_rights ()
        wrong = [ f for f in flags if f not in right ]
        if len (wrong) > 0:
            wrong = self.access_desciption (wrong)
            raise Exception ('Access denied for ' + wrong)

class Resource (DataSyncLDAP):
    """Resources are nodes in the LDAP tree of Reservoir that
       represent files and their metadata.  The actual contents
       may be downloaded, but operations exist for scuh things
       as hashing, publishing, and removing the Resource from
       the Reservoir.
        
       Users of Resource objects may want to call add_structure()
       to add classes, singular_attrs and multiple_attrs, and
       get_value(), set_value(), get_list(), set_list_elem() to
       work on the stored data describing the resource.
       
       Even though a Resource is not the place where ACL conditions
       are *defined*, they are the principal place where they need
       to be *applied*.  ACL testing is forwarded to the containing
       Collection, where the outcome will be buffered to benefit
       all Resources.
    """

    def __init__ (self, resv, parent, dn):
        """Describe a node of Reservoir in memory.  This may be
           out of sync with the data in LDAP, for instance while
           building it or after deleting it.
        """
        assert (isinstance (resv, Reservoir))
        assert (isinstance (parent, Collection))
        dn_proper_for_resource = rsdn_re.match (dn)
        assert (dn_proper_for_resource)
        DataSyncLDAP (self, resv, parent, dn)
        (res_docid, coll_uuid) = dn_proper_for_resource.groups ()
        self.coll = coll_uuid
        self.docid = res_docid
        self.created = False

    def access_require (self, flags='v'):
        self.parent.access_require (flags)

    def create (self):
        """Indicate that this Resource does not yet exist in LDAP,
           and would be created as a new instance as part of the
           current transaction.
        """
        self.access_require ('c')
        self.created = True

    def delete (self):
        """Indicate that this Resource should be taken out of LDAP,
           at least at the end of the current transaction.
        """
        self.access_require ('d')
        self.created = False
