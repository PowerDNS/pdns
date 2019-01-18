Upgrade Guide
=============

Before upgrading, it is advised to read the :doc:`changelog/index`.
When upgrading several versions, please read **all** notes applying to the upgrade.

4.1.x to 4.2.0 or master
------------------------

Two new settings have been added:

- :ref:`setting-xpf-allow-from` can contain a list of IP addresses ranges from which `XPF (X-Proxied-For) <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_ records will be trusted.
- :ref:`setting-xpf-rr-code` should list the number of the XPF record to use (in lieu of an assigned code).

4.0.x to 4.1.0
--------------

:ref:`setting-loglevel` defaulted to 4 but was always overridden to 6 during
the startup. The issue has been fixed and the default value set to 6 to keep the behavior
consistent.

The ``--with-libsodium`` configure flag has changed from 'no' to 'auto'.
This means that if libsodium and its development header are installed, it will be linked in.

4.0.3 to 4.0.4
--------------

One setting has been added to limit the risk of overflowing the stack:

-  :ref:`setting-max-recursion-depth`: defaults to 40 and was unlimited before

4.0.0 to 4.0.1
--------------

Two settings have changed defaults, these new defaults decrease CPU usage:

-  :ref:`setting-root-nx-trust` changed from "no" to "yes"
-  :ref:`setting-log-common-errors` changed from "yes" to "no"
