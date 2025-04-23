DNSSEC in the PowerDNS Recursor
===============================
As of 4.0.0, the PowerDNS Recursor has support for DNSSEC processing and experimental support for DNSSEC validation.

DNSSEC settings
---------------
The PowerDNS Recursor has 5 different levels of DNSSEC processing, which can be set with the :ref:`setting-yaml-dnssec.validation` setting in the Recursor configuration file.
In order from least to most processing, these are:

``off``
^^^^^^^
In this mode, **no** DNSSEC processing takes place.
The PowerDNS Recursor will not set the DNSSEC OK (DO) bit in the outgoing queries and will ignore the DO and AD bits in queries.

``process-no-validate``
^^^^^^^^^^^^^^^^^^^^^^^
The default mode until PowerDNS Recursor 4.5.0.

In this mode the Recursor acts as a "security aware, non-validating" nameserver, meaning it will set the DO-bit on outgoing queries and will provide DNSSEC related RRsets (NSEC, RRSIG) to clients that ask for them (by means of a DO-bit in the query), except for zones provided through the ``auth-zones`` setting.
It will not do any validation in this mode, not even when requested by the client.

``process``
^^^^^^^^^^^
The default mode since PowerDNS Recursor 4.5.0.

When :ref:`setting-yaml-dnssec.validation` is set to ``process`` the behaviour is similar to `process-no-validate`_.
However, the recursor will try to validate the data if at least one of the DO or AD bits is set in the query;
in that case, it will set the AD-bit in the response when the data is validated successfully, or send SERVFAIL when the validation comes up bogus.

``log-fail``
^^^^^^^^^^^^
In this mode, the recursor will attempt to validate all data it retrieves from authoritative servers, regardless of the client's DNSSEC desires, and will log the validation result.
This mode can be used to determine the extra load and amount of possibly bogus answers before turning on full-blown validation.
Responses to client queries are the same as with `process`_.

``validate``
^^^^^^^^^^^^
The highest mode of DNSSEC processing.
In this mode, all responses will be be validated and queries will be answered with a SERVFAIL in case of bogus data, even if the client did not request validation by setting the AD or DO bit.

**Note**: the CD-bit is honored for ``process``, ``log-fail`` and
``validate``. This mean that even if validation fails, results are
returned if the CD-bit is set by the client. For ``log-fail``, failures will be logged too.

What, when?
^^^^^^^^^^^
The descriptions above are a bit terse, here's a table describing different scenarios with regards to the ``dnssec`` mode.

+---------------+---------+-------------------------+---------------+---------------+---------------+
|               | ``off`` | ``process-no-validate`` | ``process``   | ``log-fail``  | ``validate``  |
+===============+=========+=========================+===============+===============+===============+
| Perform       | No      | No                      | Only on +AD   | Always (logs  | Always        |
| validation    |         |                         | or +DO from   | result)       |               |
|               |         |                         | client        |               |               |
+---------------+---------+-------------------------+---------------+---------------+---------------+
| SERVFAIL on   | No      | No                      | Only on +AD   | Only on +AD   | If -CD        |
| bogus         |         |                         | or +DO and    | or +DO and    | from client   |
|               |         |                         | -CD from      | -CD from      |               |
|               |         |                         | client        | client        |               |
+---------------+---------+-------------------------+---------------+---------------+---------------+
| AD in         | Never   | Never                   | Only on +AD   | Only on +AD   | Only on +AD   |
| response on   |         |                         | or +DO from   | or +DO from   | or +DO from   |
| authenticated |         |                         | client        | client        | client        |
| data          |         |                         |               |               |               |
+---------------+---------+-------------------------+---------------+---------------+---------------+
| RRSIGs/NSECs  | No      | Yes                     | Yes           | Yes           | Yes           |
| in answer on  |         |                         |               |               |               |
| +DO from      |         |                         |               |               |               |
| client        |         |                         |               |               |               |
+---------------+---------+-------------------------+---------------+---------------+---------------+

**Note**: the ``dig`` tool sets the AD-bit in the query.
This might lead to unexpected query results when testing.
Set ``+noad`` on the ``dig`` commandline when this is the case.

Trust Anchor Management
-----------------------
In the PowerDNS Recursor, both positive and negative trust anchors can be configured during startup (from a persistent configuration file) and at runtime (which is volatile).
However, all trust anchors are configurable.

Current trust anchors can be queried from the recursor by sending a query for "trustanchor.server CH TXT".
This query will (if :ref:`setting-yaml-recursor.allow_trust_anchor_query` is enabled) return a TXT record per trust-anchor in the format ``"DOMAIN KEYTAG [KEYTAG]..."``.

Trust Anchors
^^^^^^^^^^^^^
The PowerDNS Recursor ships with the DNSSEC Root key built-in.

**Note**: it has no support for :rfc:`5011` key rollover and does not persist a changed root trust anchor to disk.

Configuring DNSSEC key material can be done in the :ref:`setting-yaml-dnssec.trustanchors`.
A trust anchor entry defines the node in the DNS-tree and the data of the corresponding DS records.

To e.g. add a trust anchor for the root and example.com, use the following config:

.. code:: yaml

   dnssec:
     trustanchors:
       - name: '.'
         dsrecords:
           - '63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a' # This is not an ICANN root
       - name: example.com
         dsrecords:
           - '44030 8 2 D4C3D5552B8679FAEEBC317E5F048B614B2E5F607DC57F1553182D49 AB2179F7'

Now (re)start the recursor to load these trust anchors, or use ``rec_control reload-yaml``.

Reading trust anchors from files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is also possible to read the Trust Anchors from a BIND-style zonefile using the :ref:`setting-yaml-dnssec.trustanchorfile`.
Only the DS and DNSKEY records from this file are read.
This file is (by default) re-read every 24 hours for updates.
Debian and its derivatives ship the ``dns-root-data`` package that contains the DNSSEC root trust anchors in ``/usr/share/dns/root.key``.

Set :ref:`setting-yaml-dnssec.trustanchorfile` to this path to use these trust anchors.
Any root trust anchor in this file will override the built-in root trust anchors.

.. note::
  When using a trust anchor file, any runtime changes to Trust Anchors (see below) will be overwritten when the file is refreshed.
  To prevent this, set the :ref:`setting-yaml-dnssec.trustanchorfile_interval` parameter to ``0``.
  This will **disable** automatic reloading of the file.

Runtime Configuration of Trust Anchors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To change or add trust anchors at runtime, use the :doc:`manpages/rec_control.1` tool.
These runtime settings are not saved to disk.
To make them permanent, they should be added to the settings as described above.

Adding a trust anchor is done with the ``add-ta`` command:

::

    $ rec_control add-ta domain.example 63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a
    Added Trust Anchor for domain.example. with data 63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a

To view the currently configured trust anchors, run ``get-tas``:

::

    $ rec_control get-tas
    Configured Trust Anchors:
    .       63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a
    net.    2574 13 1 a5c5acb889a7ba9b5aa5bef2b0ac9fe1565ddaab

To remove a trust anchor, run ``clear-ta``:

::

    $ rec_control clear-ta domain.example
    Removed Trust Anchor for subdomain.example

**Note**: The root trust anchor cannot be removed in this manner.

.. _ntas:

Negative Trust Anchors
^^^^^^^^^^^^^^^^^^^^^^
Negative trust anchors (defined in :rfc:`7646`) can be used to temporarily disable DNSSEC validation for a part of the DNS-tree.
This can be done when e.g. a TLD or high-traffic zone goes bogus.
Note that it is good practice to verify that this is indeed the case and not because of malicious actions.

Current negative trust anchors can be queried from the recursor by sending a query for "negativetrustanchor.server CH TXT".
This query will (if :ref:`setting-yaml-recursor.allow_trust_anchor_query` is enabled) return a TXT record per negative trust-anchor in the format ``"DOMAIN [REASON]"``.

To configure a negative trust anchor, use the :ref:`setting-yaml-dnssec.negative_trustanchors` and restart the recursor.
The NTA entries require the name of the zone and an optional reason:

.. code-block:: yaml

  dnssec:
    negative_trustanchors:
      - name: example.com
        reason: an example

Runtime Configuration of Negative Trust Anchors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :doc:`manpages/rec_control.1` command can be used to manage the negative trust anchors of a running instance.
These runtime settings are lost when restarting the recursor, more permanent NTAs should be added to the :ref:`setting-yaml-recursor.lua_config_file` with ``addNTA()`` or to :ref:`setting-yaml-dnssec.negative_trustanchors`.

Adding a negative trust anchor is done with the ``add-nta`` command (that optionally accepts a reason):

::

    $ rec_control add-nta domain.example botched keyroll
    Added Negative Trust Anchor for domain.example. with reason 'botched keyroll'

To view the currently configured negative trust anchors, run ``get-ntas``:

::

    $ rec_control get-ntas
    Configured Negative Trust Anchors:
    subdomain.example.      Operator failed key-roll
    otherdomain.example.    DS in parent, no DNSKEY in zone

To remove negative trust anchor(s), run ``clear-nta``:

::

    $ rec_control clear-nta subdomain.example
    Removed Negative Trust Anchors for subdomain.example

``clear-nta`` accepts multiple domain-names and accepts '\*' (beware the shell quoting) to remove all negative trust anchors.
