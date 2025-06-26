DNS Modes of Operation
======================

PowerDNS offers full primary and secondary semantics for replicating domain
information. Furthermore, PowerDNS can benefit from native database
replication.

.. _native-operation:

Native replication
------------------

Native replication is the default unless another operation is
specifically configured. Native replication means that
PowerDNS will not send out DNS update notifications, nor will it react
to them. PowerDNS assumes that the backend is taking care of
replication unaided.

MySQL replication has proven to be very robust and well suited, even
over transatlantic connections between badly peering ISPs.

To use native replication, configure your backend storage to do the
replication and do not configure PowerDNS to do so.

Typically, a database secondary will be configured as read-only as
uni-directional database replication is usually sufficient. A PowerDNS
server only requires database write access if it is participating as a
primary or secondary in zone transfers, or has a frontend attached for
managing records, etc.

.. _master-operation:
.. _primary-operation:

Primary operation
-----------------

When operating as a primary, PowerDNS sends out notifications of changes
to secondaries, which react to these notifications by querying PowerDNS to
see if the zone changed, and transferring its contents if it has.
Notifications are a way to promptly signal zone changes to secondaries, as
described in :rfc:`1996`. Since
version 4.0.0, the NOTIFY messages have a TSIG record added (transaction
signature) if the zone has been configured to use TSIG and the feature has been
enabled.

.. warning::
  Primary support is OFF by default, turn it on by adding
  :ref:`setting-primary` to the configuration.
  You also need to set the type of the zones to be served as primary,
  see next warning.

.. warning::
  Notifications are only sent for domains with type PRIMARY or MASTER in
  your backend unless :ref:`setting-secondary-do-renotify` is enabled.

.. warning::
  If you have DNSSEC-signed zones and non-PowerDNS secondaries,
  please check your :ref:`metadata-soa-edit`
  settings.


Left open by :rfc:`1996` is who is to be notified - which is harder to
figure out than it sounds. All secondaries for this domain must receive a
notification but the nameserver only knows the names of the secondaries - not
the IP addresses, which is where the problem lies. The nameserver itself
might be authoritative for the name of its secondary, but not have the
data available.

To resolve this issue, PowerDNS tries multiple tactics to figure out the
IP addresses of the secondaries and notifies everybody. In contrived
configurations, this may lead to duplicate notifications being sent out,
which shouldn't hurt.

Some backends may be able to detect zone changes, others may choose to
let the operator indicate which zones have changed and which haven't.
Consult the documentation for your backend to see how it processes
changes in zones.

To help deal with secondaries that may have missed notifications, or have
failed to respond to them, several override commands are available via
the :ref:`pdns_control <running-pdnscontrol>` tool:

-  ``pdns_control notify <domain>`` This instructs PowerDNS to notify
   all IP addresses it considers to be secondaries of this domain.

-  ``pdns_control notify-host <domain> <ip-address>`` This is truly an
   override and sends a notification to an arbitrary IP address. Can be
   used in :ref:`setting-also-notify` situations or
   when PowerDNS has trouble figuring out who to notify - which may
   happen in contrived configurations.

.. _slave-operation:
.. _secondary-operation:

Secondary operation
-------------------

On launch, PowerDNS requests from all backends a list of domains that
have not been checked recently for changes. This should happen every
'**refresh**' seconds, as specified in the SOA record. All domains that
are unfresh are then checked for changes over at their primary server. If the
:ref:`types-SOA` serial number there is higher, the domain is
retrieved and updated in the database. In any case, after the check,
the domain is declared 'fresh', and will only be checked again after
'**refresh**' seconds have passed.

If the serial is equal, PowerDNS as a secondary with a presigned zone
will also compare the SOA RRSIG (signature). If the signatures are
different, the zone is also queued for a zone transfer.
This is useful when the primary server updates DNSSEC signatures without
changing the zone serial. In some configurations, a PowerDNS primary can
exhibit this behaviour.
To allow for this check, the DO flag is set on the SOA query towards
the primary server. In some conditions, some primary servers answer with
a truncated SOA response (indicating TCP is required), and the freshness
check will fail. As a workaround, the signature check and DO flag can be
turned off by disabling
:ref:`setting-secondary-check-signature-freshness` (be warned, this can lead
to expired signatures if the primary server is PowerDNS).

When the freshness of a domain cannot be checked, e.g. because the
primary is offline, PowerDNS will retry the domain after
:ref:`setting-xfr-cycle-interval` seconds.
Every time the domain fails its freshness check, PowerDNS will hold
back on checking the domain for
``amount of failures * xfr-cycle-interval`` seconds, with a maximum of
:ref:`setting-soa-retry-default` seconds
between checks. With default settings, this means that PowerDNS will
back off for 1, then 2, then 3, etc. minutes, to a maximum of 60 minutes
between checks. The same hold back algorithm is also applied if the zone
transfer fails due to problems on the primary, i.e. if zone transfer is
not allowed. Note: If the freshness check was triggered by a NOTIFY, but
the following zone transfer fails, the zone transfer will not automatically
be retried - only when a new NOTIFY is received or the refresh timer
triggers a freshness check.

Receiving a NOTIFY immediately clears the back-off period for the
respective domain to allow immediate freshness checks for this domain.

.. warning::
  Secondary support is OFF by default, turn it on by adding
  :ref:`setting-secondary` to the configuration.

.. warning::
  Only domains with type SECONDARY or SLAVE are considered for
  secondary support.

.. note::
  When running PowerDNS via the provided systemd service file,
  `ProtectSystem <https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=>`_
  is set to ``full``, this means PowerDNS is unable to write to e.g.
  ``/etc`` and ``/home``, possibly being unable to write AXFR'd zones.

PowerDNS also reacts to notifies by immediately checking if the zone has
updated and if so, retransferring it.

All backends which implement this feature must make sure that they can
handle transactions so as to not leave the zone in a half updated state.
MySQL configured with either BerkeleyDB or InnoDB meets this
requirement, as does PostgreSQL. The BIND backend implements
transaction semantics by renaming files if and only if they have been
retrieved completely and parsed correctly.

Secondary operation can also be programmed using several
:ref:`running-pdnscontrol` commands. The ``retrieve``
command is especially useful as it triggers an immediate retrieval of
the zone from the configured primary.

Since 4.5.0, zone transfers are added to a queue and processed according to priority
and order of addition. Order levels are (from high to low): pdns control,
api, notify, serial changed during refresh and signatures changed during
refresh. High priority zone transfers are always processed first, in a
first in first out order.

PowerDNS supports multiple primaries. For the BIND backend, the native
BIND configuration language suffices to specify multiple primaries, for
SQL-based backends, list all primaries servers separated by commas in the
'master' field of the domains table. For the freshness check PowerDNS will
randomly select one of the configured primaries. If the freshness checks fails
for that primary, the zone will be checked again in the next cycle, again
using one of the configured primaries, chosen at random. Hence, even with multiple primaries,
make sure that all of them are always available for fast zone updates. If
the zone refresh was triggered by a NOTIFY, PowerDNS will use the source of the
NOTIFY as target for the freshness check. Subsequent zone transfer will always
use the primary that was used for the freshness check.

Since version 4.0.0, PowerDNS requires that primaries sign their
notifications. During transition and interoperation with other
nameservers, you can use options :ref:`setting-allow-unsigned-notify` to permit
unsigned notifications. For 4.0.0 this is turned on by default, but it
might be turned off permanently in future releases.

Primary/Secondary Setup Requirements
------------------------------------

Generally to enable a Primary/Secondary setup you have to take care of
the following properties.

* The :ref:`setting-primary`/:ref:`setting-secondary` state has to be enabled in the respective ``/etc/powerdns/pdns.conf`` config files.
* The nameservers have to be set up correctly as NS domain records i.e. defining a NS and A record for each secondary.
* Primary/Secondary state has to be configured on a per-domain basis in the ``domains`` table. Namely, the ``type`` column has to be either ``MASTER`` or ``SLAVE`` respectively and the secondary needs a comma-separated list of primary node IP addresses in the ``master`` column in the ``domains`` table. :doc:`more to this topic <backends/generic-sql>`.

IXFR: incremental zone transfers
--------------------------------

If the 'IXFR' zone metadata item is set to 1 for a zone, PowerDNS will
attempt to retrieve zone updates via IXFR.

.. warning::
  If a secondary zone changes from non-DNSSEC to DNSSEC, an IXFR
  update will not set the PRESIGNED flag. In addition, a change in NSEC3
  mode will also not be picked up.

In such cases, make sure to delete the zone contents to force a fresh
retrieval.

Finally, IXFR updates that "plug" Empty Non-Terminals do not yet remove
ENT records. A 'pdnsutil zone rectify' may be required.

PowerDNS itself is currently only able to retrieve updates via IXFR. It
cannot serve IXFR updates.

.. _supermaster-operation:
.. _autoprimary-operation:

Autoprimary: automatic provisioning of secondaries
--------------------------------------------------

.. versionchanged:: 4.5.0
  Before version 4.5.0, this feature was called 'supermaster'

PowerDNS can recognize so-called 'autoprimaries'. An autoprimary is a host
which is primary for domains and for which we are to be a secondary. When a
primary (re)loads a domain, it sends out a notification to its secondaries.
Normally, such a notification is only accepted if PowerDNS already knows
that it is a secondary for a domain.

However, a notification from an autoprimary carries more persuasion. When
PowerDNS determines that a notification comes from an autoprimary and it
is bonafide, it can provision the domain automatically, and configure
itself as a secondary for that zone.

Before an autoprimary notification succeeds, the following conditions
must be met:

- :ref:`setting-autosecondary` support must be enabled
- The autoprimary must carry a SOA record for the notified domain
- The autoprimary IP must be present in the ``supermasters`` table in the database on the secondary, along with any name that is in the NS set.
- The set of NS records for the domain, as retrieved by the secondary from the autoprimary, must include the name that goes with the IP address in the ``supermasters`` table
- If your primary sends signed NOTIFY it will mark that TSIG key as the TSIG key used for retrieval as well
- If you turn off :ref:`setting-allow-unsigned-autoprimary`, then your autoprimaries are required to sign their notifications.

.. warning::
  If you use another PowerDNS server as primary and have
  DNSSEC enabled on that server please don't forget to rectify the domains
  after every change. If you don't do this there is no SOA record
  available and one requirement will fail.

So, to benefit from this feature, a backend needs to know about the IP
address of the autoprimary, and how PowerDNS will be listed in the set
of NS records remotely, and the 'account' name of your autoprimary.
There is no need to fill the account name out but it does help keep
track of where a domain comes from.
Additionally, if a secondary selects multiple autoprimaries for a zone based on the name of the primary, it also checks that the ``account`` field is the same for all.
Adding a autoprimary can be done either directly in the database,
or by using the 'pdnsutil autoprimary add' command.

.. warning::
  When a secondary receives notification while bootstrapping a new domain using autosecondary feature, it will send
  SOA and NS queries to the IP address matched in the ``supermasters`` table. These queries are **not** recursive.
  This will cause domain bootstrap to fail if the primary authoritative server is hidden behind a recursor,
  so make sure these queries go (or are forwarded by dnsdist) straight to the auth server.

.. note::
  Removal of zones provisioned using the autoprimary must be
  done on the secondaries themselves, as there is no way to signal this removal
  from the primary to the secondary.

.. _modes-of-operation-axfrfilter:

Modifying a secondary zone using a script
-----------------------------------------

The PowerDNS Authoritative Server can invoke a Lua script on an incoming
AXFR zone transfer. The user-defined function ``axfrfilter`` within your
script is invoked for each resource record read during the transfer, and
the outcome of the function defines what PowerDNS does with the records.

What you can accomplish using a Lua script:

- Ensure consistent values on SOA 
- Change incoming SOA serial number to a YYYYMMDDnn format
- Ensure consistent NS RRset
- Timestamp the zone transfer with a TXT record

This script can be enabled like this::

    pdnsutil metadata set example.com LUA-AXFR-SCRIPT /path/to/lua/script.lua

.. warning::
  The Lua script must both exist and be syntactically
  correct; if not, the zone transfer is not performed.

Your Lua functions have access to the query codes through a pre-defined
Lua table called ``pdns``. For example, if you want to check for a CNAME
record you can either compare ``qtype`` to the numeric constant 5 or the
value ``pdns.CNAME`` -- they are equivalent.

If your function decides to handle a resource record it must return a
result code of 0 together with a Lua table containing one or more
replacement records to be stored in the back-end database (if the table
is empty, no record is added). If you want your record(s) to be appended
after the matching record, return 1 and a table of record(s). If, on the
other hand, your function decides not to modify a record, it must return
-1 and an empty table indicating that PowerDNS should handle the
incoming record as normal.

Consider the following simple example:

.. code-block:: lua

        function axfrfilter(remoteip, zone, record)

           -- Replace each HINFO record with this TXT
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

           -- Grab each _tstamp TXT record and add a timestamp
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
with ``_tstamp.`` get their value (rdata) set to the current timestamp.
A records are appended with a TXT record. All other records are
unhandled.
