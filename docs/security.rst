Security of PowerDNS
====================
PowerDNS has several options to easily allow it to run more securely.
Most notable are the :ref:`setting-chroot`, :ref:`setting-setuid` and :ref:`setting-setgid` options.

For Security Advisories, see the :doc:`dedicated page <security-advisories/index>`.

.. _securitypolicy:

.. include:: common/security-policy.rst

For additional information on PowerDNS security, PowerDNS security incidents and PowerDNS security policy, see :ref:`securitypolicy`.

Securing the Process
--------------------

Running as a less privileged identity
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
By specifying :ref:`setting-setuid` and :ref:`setting-setgid`, PowerDNS changes to this identity shortly after binding to the privileged DNS ports.
These options are highly recommended.
It is suggested that a separate identity is created for PowerDNS as the user 'nobody' is in fact quite powerful on most systems.

Both these parameters can be specified either numerically or as real names.
Set these parameters immediately if they are not set!

Jailing the process in a chroot
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Modern Linux distributions, with systemd for process management, do a better job of constraining PowerDNS than chroot can.
We strongly suggest using distribution/OS features for process containment instead of the :ref:`setting-chroot` option.
The text below is kept for those users that have specific reasons to prefer chroot.
chroot functionality is not actively tested during development and might break during upgrades.

The :ref:`setting-chroot` option secures PowerDNS to its own directory so that even if it should become compromised and under control of external influences, it will have a hard time affecting the rest of the system.

Even though this will hamper hackers a lot, chroot jails have been known to be broken.

.. warning::
  When chrooting The PowerDNS, take care that backends will be able to get to their files. Many databases need access to a UNIX domain
  socket which should live within the chroot. It is often possible to
  hardlink such a socket into the chroot dir.

When running with primary or secondary support, be aware that many operating
systems need access to specific libraries (often ``/lib/libnss*``) in
order to support resolution of domain names! You can also hardlink
these.

In addition, make sure that ``/dev/log`` is available from within the chroot.
Logging will silently fail over time otherwise (on logrotate).

The default PowerDNS configuration is best chrooted to ``./``, which boils down to the configured location of the controlsocket.

This is achieved by adding the following to pdns.conf: ``chroot=./``, and restarting PowerDNS.

Security Considerations
-----------------------
In general, make sure that the PowerDNS process is unable to execute commands on your backend database.
Most database backends will only need SELECT privilege.
Take care to not connect to your database as the 'root' or 'sa' user, and configure the chosen user to have very slight privileges.

Databases empathically do not need to run on the same machine that runs PowerDNS!
In fact, in benchmarks it has been discovered that having a separate database machine actually improves performance.

Separation will enhance your database security highly. Recommended.

.. _securitypolling:

.. include:: common/secpoll.rst

Trusting zone files
-------------------
In some scenarios the PowerDNS server must handle zone files coming from an untrusted third party.
For these cases, it is recommended to take extra protective measures in addition to the measures above:

- Set :ref:`setting-max-generate-steps` to a low number, this will limit the amount of resources used by rogue ``$GENERATE`` templates.
- Set :ref:`setting-max-include-depth` to ``0``, this will disallow the ``$INCLUDE`` directive, avoiding problems with include loops and related issues.
- Set :ref:`setting-enable-lua-records` to ``no``, this will disable :ref:`Lua Records<lua-details-security>`.

Depending on your specific requirements, it might be good perform checks on zone files before loading the zone into PowerDNS to:

- Enforce reasonable ``TTL`` values.
- Enforce reasonable values in the ``SOA`` records.
- Validate delegations.
- Enforce a reasonable maximum for the total number of records.
- Enforce a reasonable maximum for the number of records per record set.
