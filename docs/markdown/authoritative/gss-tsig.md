# GSS-TSIG support

GSS-TSIG allows authentication and authorization of DNS updates or AXFR using Kerberos with TSIG signatures. NB! This feature is *experimental* and subject to change on future releases.

## Prerequisites

-   Working Kerberos environment. Please refer to your Kerberos vendor documentation on how to setup it.
-   Principal (such as DNS/<your.dns.server.name>@REALM) in either per-user keytab or system keytab.

In particular, if something does not work, read logs and ensure that your kerberos environment is ok before filing an issue. Most common problems are time synchronization or changes done to the principal.

## Setting up

To allow AXFR / DNS update to work, you need to configure GSS-ACCEPTOR-PRINCIPAL in domain metadata. This will define the principal that is used to accept any GSS context requests. This *must* match to your keytab. Next
you need to define one or more GSS-ALLOW-AXFR-PRINCIPAL entries for AXFR, or TSIG-ALLOW-DNSUPDATE entries for DNS update. These must be set to the exact initiator principal names you intend to use. No wildcards accepted.
