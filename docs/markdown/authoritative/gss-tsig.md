# GSS-TSIG (RFC 3645)
Starting for version x.x.x there is support for GSS-TSIG algorithm as specified in RFC 3645 using Kerberos/SPNEGO as mechanism. 
It is supported for authenticating and authorization of DNS updates and AXFR transfer requests from slaves. 

# Configuration options
There is only one configuration option

## `gss-default-credential`
Define the credential used as acceptor. You can leave this empty for default credential, but is very recommended that you 
set this as DNS/hostname@REALM as that is expected by nsupdate and friends. 

# Provisioning

To enable gss-tsig for a domain, add entry with name=gss-tsig, algorithm=gss-tsig, secret=gss-tsig to tsigkeys table. Then
you can use it as any other TSIG key. If you do not provide any access control entries, then any valid credential is allowed
to perform updates or AXFR. 

# Access control
For permissions, a number of per zone settings are available via the domain metadata (See [Per zone settings aka Domain Metadata](domainmetadata.md)).

## AXFR-GSS-ACL
Allow this principal or service name to AXFR this zone. Use princ:service/host@REALM or srv:service@host or srv:service. For kerberos principals you can omit princ, but it's recommended for reliable results. Use one metadata entry per pr
incipal.

## UPDATE-GSS-ACL
Allow this principal or service name to update this zone. Use princ:service/host@REALM or srv:service@host or srv:service. For kerberos principals you can omit princ, but it's recommended for reliable results. Use one metadata entry per
principal.

# Troubleshooting
Before filing a ticket, please always check following issues:
* Your DNS *must* work, there *must* be entry for your hostname, and the IP must map back to hostname.
* This applies to any clients as well (be them nameservers or other hosts)
* Time must be within few seconds between KDC, client and server. 
* Please check that your Kerberos setup works
