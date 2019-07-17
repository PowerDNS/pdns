nproxy
======

Synopsis
--------

:program:`nproxy` --powerdns-address *ADDRESS* [*OPTION*]... *ADDRESS*...

Description
-----------

:program:`nproxy` is a simple daemon that reads DNS NOTIFY queries on one
address and forwards them to an 'inner' nameserver that will process the
notification.

Its usecase is e.g. a private authoritative server inside a NAT or
firewalled LAN where :program:`nproxy` is deployed in the DMZ.

The PowerDNS Authoritative Server has the trusted-notification-proxy
option that should be set to the address set with *--origin-address* to
accept these proxied notifications.

:program:`nproxy` also has a health-check option built in. A query for
'pdns.nproxy.' with QType 'TXT' will be responded to with an answer of
"OK" (inside the TXT record. When the query is for an A-record,
'1.2.3.4.' is returned.

Options
-------

--powerdns-address <ADDRESS>        IP address of the PowerDNS server to forward the notifications to.
--chroot <PATH>                     chroot to *PATH* for additional security.
--setuid <UID>                      setuid to this numerical *UID*.
--setgid <GID>                      setgid to this numerical *GID*.
--origin-address <ADDRESS>          Set the source of the notifications sent to PowerDNS to *ADDRESS*. By default, the best matching address (kernel's choice) is used.
--listen-address <ADDRESS>          IP addresses to listen on.
--listen-port <PORT>                Source port to listen on, 53 by default.
-d, --daemon <ARG>                  Set *ARG* to 0 to disable running in the background.
-v, --verbose                       Be verbose

