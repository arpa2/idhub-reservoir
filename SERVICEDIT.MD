# ARPA2 Service Directory

> *The ARPA2 Service Directory stores configuration settings in one or more
> LDAP servers following a format that is both standard and open.*

LDAP is a useful component for configuration data, especially with the
tooling we built in the SteamWorks project.  A Pulley can subscribe to
an LDAP store and update local configurations as soon as changes come
through.  This is incredibly potent for services, and because it follows
standards it is a reasonable piece of the connecting tissue between an
identity provider for a domain (and its user base) and a plethora of
service plugin providers servicing each such domains.

Although this is powerful as a general mechanism, there may also be
use-cases for ARPA2 that are more locally managed, and perhaps less
professionally.  For such setups, we can see other storage mechanisms
than LDAP, although that could mean loosing a lot of the automation.
We would not be shocked however, to receive patches that allow the
service directory to have a backend in Python's `configparser` module,
for instance, simulating what would otherwise be done in LDAP.  We
hope to have made the structures so general that this would be doable
as a modification.


## Service Directory Structure

The structure of the Service Directory is nested, and in part standard
for all ARPA2 projects.  We go from the top down.

  * `ou=InternetWide` is the top-level, meant to separate the tree
    from any others that might run in your organisation, such as
    `dc=,dc=` style trees.

  * `o=isp.domain.nep` is the domain name of a hosting provider.  This
    level is used to allow cross-provider connections.  The intention
    is to use the same string for the same provider, even when service
    is spread over hosts; LDAP has excellent redirection mechanisms to
    redirect between such hosts if need be.  Use a lower-case zone name
    in DNS notation, without trailing dot.

    This is a very useful place to setup contact information, both when
    this node is created at another place than the ISP infrastructure
    and when others can access this node.  The information is suited for
    automation, but only available to parties that are granted access to
    this portion of the tree.

    **Please note:** This point in the tree does not mark a delegation
    of authority; this is still defined by the InternetWide Architecture.
    There are better ways of grabbing hold of a private part of the
    tree, starting from the top level.

  * `ou=ProductName` selects a standard ARPA2 application for configuration.
    A few notable examples are `ou=IdentityHub` for the identity network,
    and `ou=Reservoir`.  If you want a part of the ARPA2 Service Directory
    tree for your application, get more people involved and gain project
    consensus for a third-level application name.  This helps to avoid
    name clashes, which would be disturbing to everyone.

  * `associatedDomain=client.domain.nep` is the domain name of a customer.
    It is a DNS name in lowercase without trailing dot, but it does not
    have to be a zone name.  It must sit in a zone of your customer, of
    course, and neither be higher up in the tree nor downward-delegated
    to another service provider.  In short, you should be authoritative
    for the DNS name.  Ah well, it is of little use otherwise.

  * Starting at the fifth level are application-specific settings.  Thanks
    to the to four levels however, the attention and authority has been
    clearly set.  The exact structure is still prescribed, namely by the
    application defined in the third level, `ou=ProductName`, so turn to
    the documentation of that application for details.

Note that this setup means that one domain occurs under a multitude of
applications.  This may seem like the World on its head, but it makes a
lot of sense from the viewpoint of virtual hosting; there, one would
control the application on a particular machine, and zoom in on domains.
This is also a better privacy/security model, because knowledge can be
made available on a need-to-know basis more easily.

The automation of the InternetWide Architecture also makes it simple to
add and remove a domain in multiple places.  This is also true for a
domain user appearing in many places.

To the domain opertor, this setup is not disturbing either.  It is normal
to add services one at a time, also because DNS names and other configuration
details must be set for each service independently.  So the domain operator
will always add a <service,domain> tuple anyway.

