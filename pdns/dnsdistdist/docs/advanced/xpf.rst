Using XPF
---------

In order to provide the downstream server with the address of the real client, or at least the one talking to dnsdist, the ``addXPF`` parameter can be used when creating a :func:`new server <newServer>`.
This parameter indicates whether an experimental XPF record (from `draft-bellis-dnsop-xpf <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_) shall be added to the query. Since that record is experimental, there is currently no option code assigned to it, and therefore one needs to be specified as an argument to the ``addXPF`` parameter.

The XPF record is an alternative to the use of EDNS Client Subnet which has the advantages of preserving any existing EDNS Client Subnet value sent by the client, and of passing along the original destination address, as well as the initial source and destination ports.

If the incoming request already contains a XPF record, it will not be overwritten. Instead a new one will be added to the query and the existing one will be preserved.
That might be an issue by allowing clients to spoof their source address by adding a forged XPF record to their query. That can be prevented by using a rule to drop incoming queries containing a XPF record (in that example the 65280 option code has been assigned to XPF):

  addAction(RecordsTypeCountRule(DNSSection.Additional, 65280, 1, 65535), DropAction())

