#!/usr/bin/env python3

from arpa2 import servicedit
from arpa2 import reservoir

# Connect to LDAP (requires Kerberos login and suitable ldap.conf)
cnx = servicedit.ConnectLDAP ()
print ('Connection object is', cnx)

# Open Reservoir object
resv = reservoir.Reservoir (cnx, userdomain='example.com')
print ('Reservoir object is', resv)

# Fetch Domain and DomainUser objects from the Reservoir object
print ('Domain DN for Example is', resv.domain_dn ())
print ('Domain DN for Orvelte is', resv.domain_dn (userdomain='orvelte.nep'))
dom0 = resv.domain_node ()
dom1 = resv.domain_node (userdomain='orvelte.nep')
print ('Domain DN for Example is', dom0.home_dn (), 'or', dom0.domain ())
print ('Domain DN for Orvelte is', dom1.home_dn (), 'or', dom1.domain ())
print ('DomainUser DN for Paul at Example is', dom0.home_dn (username='paul'))
print ('DomainUser DN for Smid at Orvelte is', dom1.home_dn (username='smid'))
usr0 = dom0.home (username='johnny')
usr1 = dom1.home (username='bakker')
print ('DomainUser DN for Johnny at Example is', usr0, '::', type (usr0), 'or', usr0.user_at_domain ())
print ('DomainUser DN for Bakker at Orvelte is', usr1, '::', type (usr1), 'or', usr1.user_at_domain ())

# Create fresh Collection objects
col0p0 = dom0.create_collection ()
col0p1 = dom0.create_collection ()
col1p0 = dom1.create_collection ()
print ('Collection at Example is', col0p0.collection_uuid (), 'at', col0p0.collection_dn ())
print ('Collection at Example is', col0p1.collection_uuid (), 'at', col0p1.collection_dn ())
print ('Collection at Orvelte is', col1p0.collection_uuid (), 'at', col1p0.collection_dn ())

# Create fresh Resource objects
res0p0p0 = col0p0.create_resource ('example.col0.res0')
res0p0p1 = col0p0.create_resource ('example.col0.res1')
res0p1p0 = col0p1.create_resource ('example.col1.res0')
res1p0p0 = col1p0.create_resource ('orvelte.col0.res0')
res1p0p1 = col1p0.create_resource ('orvelte.col0.res1')
print ('Resource', res0p0p0.resource_docid (), 'at', res0p0p0.resource_dn ())
print ('Resource', res0p0p1.resource_docid (), 'at', res0p0p1.resource_dn ())
print ('Resource', res0p1p0.resource_docid (), 'at', res0p1p0.resource_dn ())
print ('Resource', res1p0p0.resource_docid (), 'at', res1p0p0.resource_dn ())
print ('Resource', res1p0p1.resource_docid (), 'at', res1p0p1.resource_dn ())
