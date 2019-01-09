pdns_notify
===========

Synopsis
--------

:program:`pdns_notify` *IP_ADDRESS/HOSTNAME*\ [:*PORT*] *DOMAIN*

Description
-----------

:program:`pdns_notify` sends a DNS NOTIFY message to *IP_ADDRESS* or *HOSTNAME*, by default
on port 53, for *DOMAIN* and prints the remote nameserver's response. If *HOSTNAME* resolves
to multiple IP addresses, each one is notified.

Options
-------

None
