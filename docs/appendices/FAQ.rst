Frequently Asked Questions
==========================

This document lists categorized answers and questions with links to the relevant documentation.

Replication
-----------
Please note that not all PowerDNS Server backends support master or slave support, see the :doc:`table of backends <../backends/index>`.

My PowerDNS Authoritative Server does not send NOTIFY messages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Don't forget to enable master-support by setting :ref:`setting-master` to ``yes`` in your configuration.
In :ref:`master mode<master-operation>` PowerDNS Authoritative Server will send NOTIFYs to all nameservers that are listed as NS records in the zone by default.

My PowerDNS Authoritative Server does not start AXFRs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Don't forget to enable slave-support by setting :ref:`setting-slave` to ``yes`` in your configuration.
In :ref:`slave mode<slave-operation>` PowerDNS Authoritative Server listens for NOTIFYs from the master IP for zones that are configured as slave zones.
And will also periodically check for SOA serial number changes at the master.

Can PowerDNS Server act as Slave and Master at the same time?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Yes totally, enable both by saying ``yes`` to :ref:`setting-master` and :ref:`setting-slave` in your configuration.

How can I limit Zone Transfers (AXFR) per Domain?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
With the ALLOW-AXFR-FROM metadata, See :ref:`the documentation <metadata-allow-axfr-from>`.

I have a working Supermaster/Superslave setup but when I remove Domains from the Master they still remain on the Slave. Am I doing something wrong?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
You're not doing anything wrong.
This is the perfectly normal and expected behavior because the AXFR (DNS Zonetransfer) Protocol does not provide for zone deletion.
You need to remove the zones from the slave manually or via a custom script.

Operational
-----------

The ADDITIONAL is section different than BIND's answer, why?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The PowerDNS Authoritative Server by default does not 'trust' other zones in its own database.

PowerDNS does not give authoritative answers, how come?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
This is almost always not the case.
An authoritative answer is recognized by the 'AA' bit being set.
Many tools prominently print the number of Authority records included in an answer, leading users to conclude that the absence or presence of these records indicates the authority of an answer. This is not the case.

Verily, many misguided country code domain operators have fallen into this trap and demand authority records, even though these are fluff and quite often misleading.
Invite such operators to look at :rfc:`section 6.2.1 of RFC 1034 <1034#section-6.2.1>`, which shows a correct authoritative answer without authority records.
In fact, none of the non-deprecated authoritative answers shown have authority records!

Master or Slave support is not working, PowerDNS is not picking up changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The Master/Slave apparatus is off by default.
Turn it on by adding a :ref:`setting-slave` and/or :ref:`setting-master` statement to the configuration file.
Also, check that the configured backend is master or slave capable and you entered exactly the same string to the Domains tables without the ending dot.

My masters won't allow PowerDNS to access zones as it is using the wrong local IP address
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
By default, PowerDNS lets the kernel pick the source address.
To set an explicit source address, use the :ref:`setting-query-local-address` and :ref:`setting-query-local-address6` settings.

PowerDNS does not answer queries on all my IP addresses (and I've ignored the warning I got about that at startup)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Please don't ignore what PowerDNS says to you.
Furthermore, see the documentation for the :ref:`setting-local-address` and :ref:`setting-local-ipv6` settings, and use it to specify which IP addresses PowerDNS should listen on.
If this is a fail-over address, then the :ref:`setting-local-address-nonexist-fail` and :ref:`setting-local-ipv6-nonexist-fail` settings might interest you.

Linux Netfilter says your conntrack table is full?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Thats a common problem with Netfilter Conntracking and DNS Servers, just tune your kernel variable (``/etc/sysctl.conf``) ``net.ipv4.netfilter.ip_conntrack_max`` up accordingly.
Try setting it for a million if you don't mind spending some MB of RAM on it for example.

Backends
--------

Does PowerDNS support splitting of TXT records (multipart or multiline) with the MySQL backend?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
PowerDNS with the :doc:`../backends/generic-sql` do NOT support this.
Simply make the "content" field in your database the appropriate size for the records you require.

I see this a lot of "Failed to execute mysql_query" or similar log-entries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Check your MySQL timeout, it may be set too low.
This can be changed in the ``my.cnf`` file.

Which backend should I use? There are so many!
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
If you have no external constraints, the :doc:`../backends/generic-mysql`, :doc:`../backends/generic-postgresql` and :doc:`../backends/generic-sqlite3` ones are probably the most used and complete.

The bindbackend is also pretty capable too in fact, but many prefer a relational database.

Can I launch multiple backends simultaneously?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
You can.
This might for example be useful to keep an existing BIND configuration around but to store new zones in, say MySQL.
The syntax to use is ``launch=bind,gmysql``.
Do note that multi-backend behaviour is not specified and might change between versions.
This is especially true when DNSSEC is involved.

I've added extra fields to the domains and/or records table. Will this eventually affect the resolution process in any way?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
No, the :doc:`../backends/generic-sql` use several default queries to provide the PowerDNS Server with data and all of those refer to specific field names, so as long as you don't change any of the predefined field names you are fine.

Can I specify custom sql queries for the gmysql / gpgsql backend or are those hardcoded?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Yes you can override the :ref:`default queries <generic-sql-queries>`.
