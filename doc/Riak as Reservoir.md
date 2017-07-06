# Riak as Reservoir

> *Riak, OpenLDAP and Nginx could be combined to
> form the Reservoir component of IdentityHub.*

The following software is used in Reservoir:

  * **Riak** as a bucket/key-indexed object store
  * **OpenLDAP** as a store for object meta data
  * **Nginx** as a web front-end
  * **Qpid** as an AMQP 1.0 sender/receiver

Riak is simple, with a focus on clustered storage and retrieval of objects in a bucket under a given key; it is however horrible at indexing them.  Instead, it assumes an outer layer that makes clever use of the key.  This is precisely what we have in mind with OpenLDAP.

Riak also does *nothing* about access control; again, this is precisely the kind of thing that we want to take care of, so we can apply the identity model of the InternetWide Architecture.

The additional parts of IdentityHub are:

  * **Authorisation** with HTTP frontend for Nginx
  * **Authentication** over TLS Pool or existing TLS
  * **ServiceDIT** to store reservoir documents
  * **LillyDAP/LEAF** to map locations and limit access

## Riak configuration

The following defines how Riak will be used:

 1. The ServiceDIT root node is `ou=Reservoir, o=internetwide.org, ou=ServiceDIT`
 1. Under this root we have `associatedDomain=`
 1. Bucket type names are domains; each defines a service level
 1. Bucket names are RDNs of a Resource Collection under the `associatedDomain=` (**TODO:** Alternatively, the `resourceClassUUID` assigned to the collection in LDAP)
 1. So, bucket names are like `cn=series-A, cn=designs`
 1. Keys in a bucket are the RDNs of a Resource relative to the containing Resource Collection
 2. We shall have a *bucket type* (service level) for each domain
 1. Resource Collections appear nested in LDAP but not in Riak

There are a few powerful facilities in Riak that will prove useful:

 1. Bucket types can declare properaties that buckets have by default
 2. [Commit hooks](https://docs.basho.com/riak/kv/2.1.3/developing/usage/commit-hooks/) are bits of Erlang code run before and after changes; they are stored as a list of operations to run in the bucket (type)
 3. [Pre-commit hooks](https://docs.basho.com/riak/kv/2.1.3/developing/usage/commit-hooks/#pre-commit-hooks) can manipulate content; it could be used to encrypt content while it is being uploaded, or to validate signatures of senders
 4. [Post-commit hooks](https://docs.basho.com/riak/kv/2.1.3/developing/usage/commit-hooks/#post-commit-hooks) can be used to store information in OpenLDAP
 5. Documents can have [metadata](http://docs.basho.com/riak/kv/2.2.3/developing/app-guide/cluster-metadata/) attached to them, also over the [HTTP API](http://docs.basho.com/riak/kv/2.2.3/developing/api/http/store-object/), which could be used to upload sender, recipient and so on
 6. Note that removal of an object also counts as a write, albeit of a [tombstone](https://docs.basho.com/riak/kv/2.0.1/using/reference/object-deletion/) &mdash; and it will therefore trigger commit hooks

## OpenLDAP/LillyDAP Configuration

OpenLDAP stores metadata in a schema that derives from the
[COSINE schema](https://tools.ietf.org/html/rfc4524)
classes for `document` and `documentSeries`.

The information is stored in the ServiceDIT, where data is collected for the service, rather than for an individual domain.  Mapping of identities will have to take place from `ou=Documents, dc=example, dc=com` to `associatedDomain=example.com, ou=Reservoir, o=internetwide.org, ou=ServiceDIT` &mdash; which can be done by OpenLDAP's aliases or by a frontend based on LillyDAP and integrated into Nginx.

The interfaces to Reservoir will all connect to the ServiceDIT for document storage.

## Nginx Configuration

Nginx will grant access to the Riak backend.  This is for internal communication; that is, a site dedicated to granting domain users and perhaps select guests to work on their and each other's files:

 1. Riak offers clustering, Nginx pooling connects to all backends
 2. Nginx authenticates the user and derives their NAI
 3. Domain, path (and user) indicate the targeted resource
 5. The requested RESTful action requires certain CRUD rights
 4. Based on this, Nginx [requests authorisation](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
 5. Only when authorised, will Nginx proxy to Riak
 6. Nginx would also deliver a few static pages to help interactions

In addition, there can be an external configuration.  In this case, the query to authorisation looks different; it asks to communicate with a given domain user.

Internal access will usually grant more rights to fewer users; external access will grant upload (resource creating) rights to most users.  The front-ends will differ completely, especially in the way that they find a Resource Collection in Riak to target.

## Authorisation Configuration

This is a good example of a resource when used as an internal website.

 1. The `resourceClassUUID` attribute is fixed to `7b679f9d-19c0-473a-b95d-ccdd41aa19b9`
 2. The `resourceInstanceKey` is not explicitly stored in LDAP, as it is the RDN relative to the Resource Collection
 3. Looking into authorisation uses the combination of these two words
 4. LDAP attributes for `owner`, `writer` and so on define DoNAI Selectors that are welcomed in such capacities (**TODO:** Alternatively, store access data under `ou=IdentityHub` in the ServiceDIT, and use a general webinterface to configure these things)
 4. SteamWorks Pully retrieves these attributes and sends them into the authorisation framework
 5. We can relax about clashes because the UID for Reservoir would not occur anywhere else
 5. LDAP may have to store half-done uploads as garbage to be collected later on (this might be a special class on the side of `resource`, to be changed soon or be garbage-collected otherwise.
 6. When querying the Global Directory, pass through authorisation; we will be sure to use caching on the computationally expensive `idmap` part; the `xsmap` should be less work, although we might optimise by limiting the search to the levels that we're interested in.  Note that access control is per Resource Collection, not per Resource.

Alternatively, a web interace could be a *drop slot* for documents, which is an example of communication when uploads and downloads are offered to external visitors.  In this case, communication would be authorised as for AMQP below.  It is in fact a HTTP variant to the Qpid tool for incoming messages; a different front-end but the same backend.  We might even imagine an MSRP variant in our SIP proxy, so we can receive documents during phone calls.

# Qpid Configuration

AMQP 1.0 is a protocol for the exchange of annotated BLOBs, possibly using the protection of TLS and/or GSSAPI.  This is our interest, as it defines a secure data push &amp; pull mechanism between domains.

It is common to store AMQP messages in queues; in our variation, we shall store it in the Reservoir and annotate with an arrival timestamp to accommodate sorting on date.

 1. We use AMQP 1.0, as is standard for Qpid.
 2. The software of interest is Qpid Proton for C++ or Go.  It would function as a server for incoming messages, and (perhaps independently) as a client for outgoing messages.
 1. AMQP accepts messages with GSSAPI protection, using the `amqp/domain.name` or `amqp/domain.name/user` format for the service principal name.
 2. As an add-on, AMQP may accept messages with TLS protection, using the TLS Pool, and picking up the `domain.name` or `user@domain.name` identity.

This is how to deal with incoming messages:

 2. AMQP uses virtual host names to group incoming messages.  These default to the authenticated domain name, and should not be explicitly set to other values (**TODO:** or let's discuss good reasons to do so).
 3. Using LDAP, make a first selection of suitable Resource Collection.  A match is made on matching the sender, recipient, document MIME-type (first component or both).  This selection is ordered for best-to-least suitable.
 4. Given potential Resource Collections for an incoming message, authorisation is used to evaluate communication access form the sender to the resource collection's owner, and also for the associated ACLs for the resource.
 5. It is normal for authorisation to suggest the authorisation identity that matches an ACL.  This should be used to replace the incoming identity.  (**TODO:** Under evaluation.)
 3. Incoming message data is stored in LDAP, initially as a document being uploaded.  It is always a new Resource being created.  The data stored in LDAP reflects the metadata being used.
 4. Once ready to go, the message is uploaded to Riak over it's object creation interface (the RESTful `POST` method, while supplying a key).
 5. After the upload succeeded, the LDAP entry is upgraded from an UploadingResource to a Resource, and only then is an acknowledgement sent back over AMQP.

This is how to send outgoing messages:

 1. Look for messages under `/var/outgoing/<recipient.domain>`
 2. Messages are `<uuid>.msg` and `<uuid>.json`, the latter of which holds metadata such as MIME-type, subject, sender, recipient, ... and finally there is a `flock()` mechanism on `<uuid>.lock` to ensure that only one sending mechanism is triggered at any time.  Keep this lock for as long as a message delivery is opportune, but drop it as soon as possible afterwards.
 3. In addition, you can create `<uuid>.amqp.json` with metadata dedicated to AMQP.
 4. Expect other sender too, so `<uuid>.xmpp.json`, `<uuid>.smtp.json`, `<uuid>.msrp.json`, `<uuid>.sms.json` &mdash; and expect those to be trying just as hard to deliver the message.  
 5. There will be a certain order for delivery attempts, determined by each domain or perhaps even per sender or message.  This is reflected in the `<uuid>.amqp.json` file, which indicates other submissions that must first have been tried.  **TODO:** What, where, how?
 4. Try, with exponential fallback, to deliver the messages to their respective domains.  Connect, authenticate as the sender domain, lock a message to send, offer for delivery.  When failed or timed out, retract submission and unlock.

**TODO:** Differentiate frontend and backend.  The frontend can vary wildly: AMQP, HTTP, SFTP, OwnCloud, Dropbox, CSync, ...  The backend is always the same.  A similar reasoning applies to both sending and receiving.

# Experiment: Frontends/Backend

> *Where we explore how to split generic from specific...*


## Backend Design: Outgoing

Outgoing backends are quite simply LDAP queues with outgoing Resources.  They are annotated with the metadata to be sent, which includes a reference to the object.

The backend is stored in the ServiceDIT, perhaps under the node for Reservoir, or another one.  Note that this means that the queued elements are not immediately visible to their senders.

It is unlikely that LDAP will turn out to be a poor choice; even just the ability to *atomically* change a date for next submission from the old value to one in the future can be interpreted as holding a lock until that moment in the future.  This could be allocated per domain, and/or per outgoing Resource.

**TODO:** Define a single-valued `lockedUntil` attribute with a timestamp, as well as an auxiliary class `lockedObject` that must have this attribute.

**TODO:** Define a class `domainQueue` and/or specific `outgoingQueue` and `incomingQueue` classes which subclass the Resource Collection class.  This should have a domain name, and must/may have the `lockedUntil` attribute (or a variation named `deferUntil` and something helpful for exponential fallback, like `deferStep` and `expireAt`).  The collection of failures under a domain sounds like a clever way to reduce delivery attempts, and to group them.

**TODO:** Think about encryption and/or signing for incoming/outgoing queues.  Enforcing and opportunistic variants.

**TODO:** Think about redirection of content, including to AMQP 1.0 services downstream.  This may be done by specifying an outgoing connection for content; there may also be a use for specifying incoming parameters, such as host/protocol/port and perhaps vhost/exchange/queue.

**TODO:** Define a class `queuedResource` that has a sender and recipient, title/subject, MIME-type and any other annotations that may be of use, including signatures and hashes.

Even though LDAP as a protocol seems useful, we may find that OpenLDAP or any other LDAP implementation is a less suitable match.  If that is the case, we can still build a queue in `/var/messaging` with an LDAP interface, and redirect certain portions on a directory there.

To submit a resource, the user would add an object description, founded on the original object, in the outgoing queue targeting the recipient domain.  The creation of a new domain queue may be noted of SyncRepl, perhaps using SteamWorks Pulley.

## Frontend Design: Outgoing

Frontends for Reservoir can delivery over a multitude of protocols, and they would inspect published announcements such as in DNS to see what would be acceptable.

There are two changes to outgoing messages, namely notification and delivery.  Not all protocols distinguish the two.  Especially when manual labour is involved, such as when clicking a link in an email, the delay may be long and should be avoided if possible.

A possible order of delivery attempts could be:

  * AMQP 1.0 &mdash; notification means sending, as delivery counts when reception is acknowledged.  Ideal when the remote has an incoming queue and possibly sorts traffic based on what type it is.  We should be able to get a hard failure from AMQP when it refuses to take in the message.
  * [MSRP] &mdash; document delivery while sender and recipient are calling.  Not likely to be appreciated much with the current use of telephony.
  * XMPP &mdash; notification by attempting file transfer, delivery when arrived; only when recipient sends status info to the sender, who must therefore be on their roster, and only when the recipient is online and/or taking uploads.
  * SMTP &mdash; email attachment for short documents, otherwise a download link.  This involves human labour, and so is a delivery method of last resort.
  * [SMS] &mdash; notification with download link only.  Not particularly useful, it would seem.

The best thing that a frontend can do is try the various options in sequence.  After a first failure however, it may prove interesting to process hints by domains and users coming online over a certain protocol.

The object is only passed by reference; it remains in the Riak backend and is assumed to not be deleted until delivery completes.

Upon failure to deliver, a notification would be sent to the sender, with a description of the submission but not the actual object.

## Frontend Design: Incoming

There can be multiple front-ends that all take in messages from remote users:

  * An AMQP 1.0 listener may accept messages from authenticated senders, provided that communication is authorised for the intended sender.
  * [An MSRP proxy server may be active during a SIP phone call, to take in documents related to that call.]
  * An XMPP server may take in offered document uploads from people who are on our roster, and/or it may apply authorisation on communication.  It may be useful to allow this mechanism only while the recipient is actively involved in a chat with the sender.
  * An SMTP attachment will probably be passed on manually, unless a mail provider chooses to strip off all attachments and always store them in the Reservoir, linked to from the email.
  * An HTTP frontend can take *drop slot* deliveries from authenticated clients (certificate, Kerberos, ...) who have communication authorisation to the intended recipient.
  * MMS may be used to deliver media over HTTP to oneself.  Only the attachments would be of interest, the rest ending up in its metadata.  This is an easy way to collect photos and videos into one's repository and, given the HTTP upload, rather inexpensive too.  When non-self recipients are specified, their numbers are changed to addresses using ENUM and their email addresses interpreted as NAIs, so an outgoing transfer to those addresses can be initiated after the upload to Reservoir.

It is quite likely that users will want to ban a mechanism altogether; for instance, XMPP uploads are highly disruptive and may only be tolerable while actively engaged in a chat session.

## Backend Design: Incoming

When incoming messages are stored, their data enters Riak and their metadata ends up in LDAP.

Each user should have created an incoming Queue that is in their line of sight.  This is a special form of Resource Collection under their `uid=,...,dc=,dc=` node that is specifically meant for the reception of new objects.  The Resource Collection has its specifications, and may or may not welcome the intended transfer.  There may, for instance, be a blacklist entry for the intended sender.

An incoming queue is by default meant as a bucket in which to store messages; and indeed, messages end up as objects in Riak.  An overriding option that is also possible, is to forward the message (over AMQP 1.0) to a host, transport and port elsewhere.  This can be used to tap particular kinds of messages and deal with them in a special manner.

There may be more than one incoming queue; some may match better than others.  The frontend chooses the one that seems most useful to a given incoming message, based on descriptive information such as MME-type, sender, recipient and ACL permissions to communicate.  **TODO:** Alternatively, the frontend may locate a compiled [Sieve](http://sieve.info) script to help with message routing.  It is probably useful to allow such a script in any incoming queue, to be able to override automated awkward choices.  Note that the frontend will need to support Sieve, and [LDAP attributes](https://docs.oracle.com/cd/E19563-01/819-4437/6n6jckqva/index.html) or a bucket entry may be needed to store it.

While in transit, an LDAP node marked as an uploading document is created.  When done, it is upgraded to a normal Resource.
