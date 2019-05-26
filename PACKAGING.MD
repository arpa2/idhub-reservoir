# ARPA2 General Packaging (Python)

> *The names and structures of ARPA2 packages for Python.*


## Conceptual APIs

The conceptual components of ARPA2 involve modules for operational control:

  - Identity Management
  - Reservoir for Annotated Data
  - Access Control
  - Technical Components

These are available as

```
from arpa2 import @concept@
```

Examples of `@concept@` are:

  - `identity` for Identity Management
  - `reservoir` for the Reservoir of Annotated Data
  - `acl` for Access Control

as well as Technical Components:

  - `servicedit` for general use of a Service DIT (usually LDAP)
  - `quick_der` for ASN.1 processing
  - `quick_sasl` for SASL processing
  - `kip` for instant encryption
  - `tlspool` for externalised TLS


## Shells for Operator Control

The shells reside in a name space of their own,

```
from arpa2shell import arpa2@topic@
```

Examples of `arpa2@topic` are:

  - `arpa2id` for the Identity Management shell
  - `arpa2reservoir` for the Reservoir shell
  - `arpa2acl` for the ACL shell

The namespace `arpa2shell` also hosts support tools for JSON over
AMQP.  The shells tend to require one or more Conceptual API packages
for the hard work.


## ASN.1 Modules for Quick DER

The base package for Quick DER is an ARPA Technical Component,

```
# With the standard prefix
from arpa2 import quick_der
# Abbreviated prefix
from arpa2 import quick_der as _api
```

This is also where the entry points for `asn2quickder`, `asn1literate`
and `derdump` sit.

In addition, precompiled definitions are packaged to allow forms like

```
# General import
from quick_der import rfc5280
# Provider-specific import
from quick_der import arpa2.RemotePKCS11
```


## Package names

The work described above may be packaged in a number of ways.
Probably, the structures will be like

  - `arpa2shell` for meta-shell support plus JSON over AMQP service
  - `arpa2shell-reservoir`, `arpa2shell-identity` for specific shells
  - `quick-der` for ASN.1 tools and core package `arpa2.quick_der`
  - `quick-sasl` for SASL end servers and clients
  - `quick-der-rfc`, `quick-der-arpa2` for the RFC lists from IETF and ARPA2
  - `tlspool`, `kip`, `arpa2-servicedit` for technologies
  - `arpa2-reservoir`, `arpa2-identityhub` for the Conceptual APIs

