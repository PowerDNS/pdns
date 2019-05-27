.. _ACL:

Access Control
==============

dnsdist can be used to front traditional recursive nameservers, these usually come with a way to limit the network ranges that may query it to prevent becoming an :term:`open resolver`.
To be a good internet citizen, dnsdist by default listens on the loopback address (`127.0.0.1:53`) and limits queries to these loopback, :rfc:`1918` and other local addresses:

- ``127.0.0.0/8``
- ``10.0.0.0/8``
- ``100.64.0.0/10``
- ``169.254.0.0/16``
- ``192.168.0.0/16``
- ``172.16.0.0/12``
- ``::1/128``
- ``fc00::/7``
- ``fe80::/10``

The ACL applies to queries received over UDP, TCP, DNS over TLS and DNS over HTTPS.

Further more, dnsdist only listens for queries on the local-loopback interface by default.

Listening on different addresses
--------------------------------

To listen on other addresses than just the local addresses, use :func:`setLocal` and :func:`addLocal`.

:func:`setLocal` **resets** the list of current listen addresses to the specified address and :func:`addLocal` adds an additional listen address.
To listen on ``127.0.0.1:5300``, ``192.0.2.1:53`` and UDP-only on ``[2001:db8::15::47]:53``, configure the following:

.. code-block:: lua

  setLocal('127.0.0.1:5300')
  addLocal('192.0.2.1') -- Port 53 is default is none is specified
  addLocal('2001:db8::15::47', false)

Listen addresses cannot be modified at runtime and must be specified in the configuration file.

As dnsdist is IPv4 and IPv6 agnostic, this means that dnsdist internally does not know the difference.
So feel free to listen on the magic ``0.0.0.0`` or ``::`` addresses, dnsdist does the right thing to set the return address of queries, but set your :term:`ACL` properly.

Modifying the ACL
-----------------

ACLs can be modfied at runtime from the :ref:`Console`.
To inspect the currently active :term:`ACL`, run :func:`showACL`.

To add a new network range to the existing ACL, use :func:`addACL`:

.. code-block:: lua

  addACL('192.0.2.0/25')
  addACL('2001:db8::1') -- No netmask specified, only allow this address

dnsdist also has the :func:`setACL` function that accepts a list of netmasks and resets the ACL to that list:


.. code-block:: lua

  setACL({'192.0.2.0/25', '2001:db8:15::bea/64'})

