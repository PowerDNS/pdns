DNS Modes of Operation
======================

PowerDNS offers full master and slave semantics for replicating domain
information. Furthermore, PowerDNS can benefit from native database
replication.

.. _native-operation:

Native replication
------------------

Native replication is the default, unless other operation is
specifically configured. Native replication basically means that
PowerDNS will not send out DNS update notifications, nor will react to
them. PowerDNS assumes that the backend is taking care of replication
unaided.

MySQL replication has proven to be very robust and well suited, even
over transatlantic connections between badly peering ISPs.

To use native replication, configure your backend storage to do the
replication and do not configure PowerDNS to do so.

Typically, a database slave will be configured as read-only as
uni-directional database replication is usually sufficient. A PowerDNS
server only requires database write access if it is participating as a
master or slave in zone transfers, or has a frontend attached for
managing records etc.

.. _master-operation:

Master operation
----------------

When operating as a master, PowerDNS sends out notifications of changes
to slaves, which react to these notifications by querying PowerDNS to
see if the zone changed, and transferring its contents if it has.
Notifications are a way to promptly propagate zone changes to slaves, as
described in :rfc:`1996`. Since
version 4.0.0, the NOTIFY messages have a TSIG record added (transaction
signature) if zone has been configured to use TSIG and feature has been
enabled.

.. warning::
  Master support is OFF by default, turn it on by adding
  :ref:`setting-master` to the configuration.

.. warning::
  If you have DNSSEC-signed zones and non-PowerDNS slaves,
  please check your :ref:`metadata-soa-edit`
  settings.

.. warning::
  Notifications are only sent for domains with type MASTER in
  your backend unless :ref:`setting-slave-renotify` is enabled.

Left open by :rfc:`1996` is who is to be notified - which is harder to
figure out than it sounds. All slaves for this domain must receive a
notification but the nameserver only knows the names of the slaves - not
the IP addresses, which is where the problem lies. The nameserver itself
might be authoritative for the name of its secondary, but not have the
data available.

To resolve this issue, PowerDNS tries multiple tactics to figure out the
IP addresses of the slaves, and notifies everybody. In contrived
configurations this may lead to duplicate notifications being sent out,
which shouldn't hurt.

Some backends may be able to detect zone changes, others may chose to
let the operator indicate which zones have changed and which haven't.
Consult the documentation for your backend to see how it processes
changes in zones.

To help deal with slaves that may have missed notifications, or have
failed to respond to them, several override commands are available via
the :ref:`pdns_control <running-pdnscontrol>` tool:

-  ``pdns_control notify <domain>`` This instructs PowerDNS to notify
   all IP addresses it considers to be slaves of this domain.

-  ``pdns_control notify-host <domain> <ip-address>`` This is truly an
   override and sends a notification to an arbitrary IP address. Can be
   used in :ref:`setting-also-notify` situations or
   when PowerDNS has trouble figuring out who to notify - which may
   happen in contrived configurations.

.. _slave-operation:

Slave operation
---------------

On launch, PowerDNS requests from all backends a list of domains which
have not been checked recently for changes. This should happen every
'**refresh**' seconds, as specified in the SOA record. All domains that
are unfresh are then checked for changes over at their master. If the
:ref:`types-SOA` serial number there is higher, the domain is
retrieved and inserted into the database. In any case, after the check
the domain is declared 'fresh', and will only be checked again after
'**refresh**' seconds have passed.

When the freshness of a domain cannot be checked, e.g. because the
master is offline, PowerDNS will retry the domain after
:ref:`setting-slave-cycle-interval` seconds.
Every time the domain fails it's freshness check, PowerDNS will hold
back on checking the domain for
``amount of failures * slave-cycle-interval`` seconds, with a maximum of
:ref:`setting-soa-retry-default` seconds
between checks. With default settings, this means that PowerDNS will
back off for 1, then 2, then 3 etc. minutes, to a maximum of 60 minutes
between checks. The same hold back algorithm is also applied if the zone
transfer fails due to problems on the master, i.e. if zone transfer is
not allowed.

Receiving a NOTIFY immediately clears the back off period for the
respective domain to allow immediately freshness checks for this domain.

.. warning::
  Slave support is OFF by default, turn it on by adding
  :ref:`setting-slave` to the configuration.

.. note::
  When running PowerDNS via the provided systemd service file,
  `ProtectSystem <http://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=>`_
  is set to ``full``, this means PowerDNS is unable to write to e.g.
  ``/etc`` and ``/home``, possibly being unable to write AXFR's zones.

PowerDNS also reacts to notifies by immediately checking if the zone has
updated and if so, retransfering it.

All backends which implement this feature must make sure that they can
handle transactions so as to not leave the zone in a half updated state.
MySQL configured with either BerkeleyDB or InnoDB meets this
requirement, as do PostgreSQL. The BIND backend implements
transaction semantics by renaming files if and only if they have been
retrieved completely and parsed correctly.

Slave operation can also be programmed using several
:ref:`running-pdnscontrol` commands. The ``retrieve``
command is especially useful as it triggers an immediate retrieval of
the zone from the configured master.

PowerDNS supports multiple masters. For the BIND backend, the native
BIND configuration language suffices to specify multiple masters, for
SQL based backends, list all master servers separated by commas in the
'master' field of the domains table.

Since version 4.0.0, PowerDNS requires that masters sign their
notifications. During transition and interoperation with other
nameservers, you can use options :ref:`setting-allow-unsigned-notify` to permit
unsigned notifications. For 4.0.0 this is turned on by default, but it
might be turned off permanently in future releases.

Master/Slave Setup Requirements
-------------------------------

Generally to enable a Master/Slave setup you have to take care of
following properties.

* The :ref:`setting-master`/:ref:`setting-slave` state has to be enabled in the respective ``/etc/powerdns/pdns.conf`` config files.
* The nameservers have to be set up correctly as NS domain records i.e. defining a NS and A record for each slave.
* Master/Slave state has to be configured on a per domain basis in the ``domains`` table. Namely the ``type`` column has to be either ``MASTER`` or ``SLAVE`` respectively and the slave needs a comma separated list of master node IP addresses in the ``master`` column in the ``domains`` table. :doc:`more to this topic <backends/generic-sql>`.

IXFR: incremental zone transfers
--------------------------------

If the 'IXFR' zone metadata item is set to 1 for a zone, PowerDNS will
attempt to retrieve zone updates via IXFR.

.. warning::
  If a slave zone changes from non-DNSSEC to DNSSEC, an IXFR
  update will not set the PRESIGNED flag. In addition, a change in NSEC3
  mode will also not be picked up.

In such cases, make sure to delete the zone contents to force a fresh
retrieval.

Finally, IXFR updates that "plug" Empty Non Terminals do not yet remove
ENT records. A 'pdnsutil rectify-zone' may be required.

PowerDNS itself is currently only able to retrieve updates via IXFR. It
can not serve IXFR updates.

.. _supermaster-operation:

Supermaster: automatic provisioning of slaves
---------------------------------------------

.. versionchanged:: 4.2.0
  Supermaster support needs to be explicitly enabled with the
  :ref:`setting-superslave` setting.

PowerDNS can recognize so called 'supermasters'. A supermaster is a host
which is master for domains and for which we are to be a slave. When a
master (re)loads a domain, it sends out a notification to its slaves.
Normally, such a notification is only accepted if PowerDNS already knows
that it is a slave for a domain.

However, a notification from a supermaster carries more persuasion. When
PowerDNS determines that a notification comes from a supermaster and it
is bonafide, it can provision the domain automatically, and configure
itself as a slave for that zone.

Before a supermaster notification succeeds, the following conditions
must be met:


- :ref:`setting-superslave` support must be enabled
- The supermaster must carry a SOA record for the notified domain
- The supermaster IP must be present in the 'supermaster' table
- The set of NS records for the domain, as retrieved by the slave from the supermaster, must include the name that goes with the IP address in the supermaster table
- If your master sends signed NOTIFY it will mark that TSIG key as the TSIG key used for retrieval as well
- If you turn off :ref:`setting-allow-unsigned-supermaster`, then your supermaster(s) are required to sign their notifications.

.. warning::
  If you use another PowerDNS server as master and have
  DNSSEC enabled on that server please don't forget to rectify the domains
  after every change. If you don't do this there is no SOA record
  available and one requirement will fail.

So, to benefit from this feature, a backend needs to know about the IP
address of the supermaster, and how PowerDNS will be listed in the set
of NS records remotely, and the 'account' name of your supermaster.
There is no need to fill the account name out but it does help keep
track of where a domain comes from.

.. note::
  Removal of zones provisioned using the supermaster must be
  done on the slaves themselves. As there is no way to signal this removal
  from the master to the slave.

.. _modes-of-operation-axfrfilter:

Modifying a slave zone using a script
-------------------------------------

The PowerDNS Authoritative Server can invoke a Lua script on an incoming
AXFR zone transfer. The user-defined function ``axfrfilter`` within your
script is invoked for each resource record read during the transfer, and
the outcome of the function defines what PowerDNS does with the records.

What you can accomplish using a Lua script: - Ensure consistent values
on SOA - Change incoming SOA serial number to a YYYYMMDDnn format -
Ensure consistent NS RRset - Timestamp the zone transfer with a TXT
record

To enable a Lua script for a particular slave zone, determine the
``domain_id`` for the zone from the ``domains`` table, and add a row to
the ``domainmetadata`` table for the domain. Supposing the domain we
want has an ``id`` of 3, the following SQL statement will enable the Lua
script ``my.lua`` for that domain:

.. code-block:: SQL

    INSERT INTO domainmetadata (domain_id, kind, content) VALUES (3, "LUA-AXFR-SCRIPT", "/lua/my.lua");

.. warning::
  The Lua script must both exist and be syntactically
  correct; if not, the zone transfer is not performed.

Your Lua functions have access to the query codes through a pre-defined
Lua table called ``pdns``. For example if you want to check for a CNAME
record you can either compare ``qtype`` to the numeric constant 5 or the
value ``pdns.CNAME`` -- they are equivalent.

If your function decides to handle a resource record it must return a
result code of 0 together with a Lua table containing one or more
replacement records to be stored in the back-end database (if the table
is empty, no record is added). If you want your record(s) to be appended
after the matching record, return 1 and table of record(s). If, on the
other hand, your function decides not to modify a record, it must return
-1 and an empty table indicating that PowerDNS should handle the
incoming record as normal.

Consider the following simple example:

.. code-block:: lua

        function axfrfilter(remoteip, zone, record)

           -- Replace each HINFO records with this TXT
           if record:qtype() == pdns.HINFO then
              resp = {}
              resp[1] = {
                qname   = record:qname():toString(),
                qtype   = pdns.TXT,
                ttl     = 99,
                content = "Hello Ahu!"
             }
              return 0, resp
           end

           -- Grab each _tstamp TXT record and add a time stamp
           if record:qtype() == pdns.TXT and string.starts(record:qname():toString(), "_tstamp.") then
              resp = {}
              resp[1] = {
                qname   = record:qname():toString(),
                qtype   = record:qtype(),
                ttl     = record:ttl(),
                content = os.date("Ver %Y%m%d-%H:%M")
              }
              return 0, resp
           end

           -- Append A records with this TXT
           if record:qtype() == pdns.A then
              resp = {}
              resp[1] = {
                qname   = record:qname():toString(),
                qtype   = pdns.TXT,
                ttl     = 99,
                content = "Hello Ahu, again!"
              }
              return 1, resp
           end

           resp = {}
           return -1, resp
        end

        function string.starts(s, start)
           return s.sub(s, 1, s.len(start)) == start
        end

Upon an incoming AXFR, PowerDNS calls our ``axfrfilter`` function for
each record. All HINFO records are replaced by a TXT record with a TTL
of 99 seconds and the specified string. TXT Records with names starting
with ``_tstamp.`` get their value (rdata) set to the current time stamp.
A records are appended with a TXT record. All other records are
unhandled.
