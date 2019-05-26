# ARPA2 Service Directory: Reservoir

> *Reservoir is the storage system for objects with meta-data.  It connects
> to an abundance of protocols and is key in keeping them compatible and
> exchangeable.  To allow smooth co-operation between pieces of software,
> a standard model is helpful.*

Reservoir sits in the Service Directory on nodes named

```
associatedDomain=<hosted.domain>,ou=Reservoir,o=<isp.dns.zone>,ou=InternetWide
```

There are a few variations underneath this.

LDAP is used to store meta-data for Reservoir, but not the objects.  For
the data blobs, an object store (such as Riak KV) or perhaps a distributed
hash table (such as IPFS) or just a file system is assumed to be active.

It may be useful to separate the Reservoir from the configuration stores
in LDAP.  This would improve security and privacy, and simplify management.
The tree structure of the Service Directory was designed to make this easy.


### Resources in terms of the Service Directory

Though unpleasantly confusing, the Service Directory has another
name definition for resources.  These however, are LDAP terms and
not end-user terms as is the case with the name used by Reservoir.

The `associatedDomain` node at the fourth level, underneath the
`ou=Reservoir`, holds obliged attributes to identify it as a
Reservoir node and help applications to a strong selector,

```
objectClass: resourceClassObject
resourceClassUUID: 904dfdb5-6b34-3818-b580-b9a0b4f7e7a9
```

Similarly, every `reservoirCollection` and every `reservoirIndex`
defined below holds the following obliged attributes to scope it
for the Reservoir application:

```
objectClass: resourceInstanceObject
resourceClassUUID: 904dfdb5-6b34-3818-b580-b9a0b4f7e7a9
resins: ...
```

The value `904dfdb5-6b34-3818-b580-b9a0b4f7e7a9` is defined in
the registry at `uuid.arpa2.org`.  This UUID is used when looking
in the ACL for access rights, as defined below.  The `resins`
attribute is also set to a UUID in lowercase notation, is often
referred to as the Collection UUID, and identifies a Resource
Collection in Reservoir when the `resourceClassUUID` is set
to the 904dfdb5-6b34-3818-b580-b9a0b4f7e7a9` value of Reservoir.


## Reservoir offers Collections of Resources

The most important levels added under the Service Directory base node
are:

  * `resins=<CollectionUUID>` is an instance of the ACL notion of a
    Resource, but to the Reservoir it is a Collection node.  That may
    be confusing, but the `objectClass: reservoirCollection` should be
    clear enough.  The additional `objectClass: resourceInstanceObject`
    simply represents another view on the data.  The `<CollectionUUID>`
    is just a UUID in lowercase textual notation.  Random generation
    (type 4) seems quite acceptable due to the incredibly low risk of
    a name clash.

  * TODO is a Resource in terms of Reservoir,
    recognisable by the `objectClass: reservoirResource` for these
    nodes.

It is important to understand that this is a two-level structure,
so only levels 5 and 6 of the Service Directory are covered.
Even if LDAP could handle a nested structure during searches, it
is still complicating for all other software.

This does not mean that no nesting of collections can be offered as
part of a Reservoir service.  The practically unique UUID however,
always allows direct addressing of a `reservoirCollection`, and the
same holds for a `reservoirResource`.  This is arranged through the
`reservoirIndex` concept.


## Indexes to Collections

An index is a set of names used to reference `reservoirCollection`
objects.  As in a file system, the names are scoped under the node
that holds them, so the same name can have different meaning in
different places, allowing it to be short and user-friendly.  Also,
multiple names can point to the same `reservoirCollection` object.

Since every `reservoirCollection` is uniquely identifiable with its
UUID, that is all we need to store in an index to reference the
object.  Indeed, `objectClass: reservoirIndex` specifies zero or
more attributes

```
collectionRef: <CollectionUUID> <humanName>
```

(there is a special form, dropping the space and `<humanName>` to define
the default entry of this index)

The `<CollectionUUID>` is not resolved globally in the Reservoir, but
instead underneath the client domain under which the index object resides.
This avoids abusive patterns where another user's `<CollectionUUID>` is
replicated in another domain's Reservoir, intending it to overrule perhaps
security arrangements.  The nice result is that the path to the referenced
collection can be constructed without looking in LDAP.

There is an option in indexes for remote references, but it uses another
form of attribute,

```
reservoirRemoteRef: <RemoteURI> <humanName>
```

(this form can also specify a default when the space and `<humanName>` are
dropped)

It would be confuse to define the same `<humanName>` or the default more
than once across the `collectionRef` and `reservoirRemoteRef` in an index.


So, where do we currently support indexes?

  * Every `reservoirCollection` object is automatically a `reservoirIndex`
    object.  This allows nested structures to be simulated in the flat
    collection list at the fifth level.  Note that branches may be merged
    if they reference the same `<CollectionUUID>` in multiple places, but
    if this is not done there would be completely independent trees.

  * Various "entry nodes" can attach a `reservoirIndex` to define a root
    point in the Reservoir hierarchy.  See below for examples.


## Entry Points for Users, Groups, Services, ...

We now have an internal structure for Collections of Resources.  All we
need is to get in.  So we now turn to entry points.  These are defined
for various beings in the InternetWide Identity Architecture:

  * Users, groups, roles, aliases can all have a starting node.

  * Services can have a starting node.

Both of these have a `uid` attribute, and this is indeed how they are
represented in LDAP.  The name spaces do not overlap, given a domain name
under which the Reservoir sits.  This means that we add the following
levels to LDAP *next to the Collections of Resources*, so we have the
following combined levels 5 and 6 in the Service Directory:

  * `ou=Users` collects the large set of nodes to follow.

  * `uid=<UserID>` provides the local part of an ARPA2 user identity.
    Examples might be `john` for a user, `john+bookfan` for an alias,
    `members` for a group, `admin` for a role, `members+john` for a
    group and `admin+john` for a role occupant.

    Services follow the same pattern, but as defined for ARPA2 Identities
    their name starts with a plus sign.  It is up to the service how many
    more levels it wants to add; these entries will usually be looked up
    by a service.  Examples are therefore `+web` and `+web+blog` and a
    possible use of the latter could be to retrieve blog articles that need
    to be produced for a URI path that traces collections.


## Support for Queueing and Locking

An experimental object `reservoirQueue` has been defined to allow the
storage of queue entries.  These may be added and removed under different
rules than the usual `reservoirCollection`.

The `lockableObject` is another experimental class that *may* have an
attribute `lockedBy` defining the lock owner.  When this attribute is
absent, the object is considered unlocked in spite of having the class
to signal that locking is supported.  This is a co-operative locking
scheme, nothing but that various LDAP applications implement it.


## Access Control

Reservoir does not constrain access to individual `reservoirResource` ojects;
instead, the `reservoirCollection` scopes access.  Due to the possibility
of addressing each Collection directly by its UUID, only the Collection
that directly contains the Resource can be relied upon to filter access.
In practice, visibility of surrounding Collections could be used to
*discourage visibility* of a Collection, but this must not be relied upon
as a mechanism of security of privacy.

Since the LDAP path to a resource involves the `resins=<CollectionUUID>`,
it is possible to directly use the ACL to test access rights.  Again, the
ACL terminology is a `resourceInstance` (or `resins` for short) but this
should not be confused with the Reservoir terminology of a
`reservoirResource`.  The form `resins` for the fifth level of an LDAP
path is obligatory, precisely to enable this kind of interpretation of
the textual path, and thereby avoid going through LDAP to evaluate the
ACL.  Light ACLs can be used without restraint, which is helpful to
exercise control over one's online presence.

Access Control rules are stored as part of the Reservoir tree.  This is
because they are indeed access rules for the Reservoir application, and
the Service Directory branch for `ou=Reservoir` is authoritative.  To
implement this, a `resourceCollection` object must also be an
`accessControlledObject`.  The various ACL rules can then be setup in
`accessControlLine` attributes.

Note that the UUID values that define the Reservoir are used as the
resource UUID in the ACL, and because they are fixed given the
application it is not necessary to look in LDAP for them either.
All we need is the `resins` which is in the path.
