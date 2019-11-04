Getting Started
===============
The PowerDNS Recursor can be installed on any modern unix-like system and is available in the software repositories for all major Linux distributions and BSDs.

Installation
------------
The Recursor is available for many platforms, instructions are provided here for several platforms.

**note**: PowerDNS itself provides repositories for several Recursor versions for different operating systems.
Checkout `the repositories <https://repo.powerdns.com>`_ for more information.

Debian-based distributions
^^^^^^^^^^^^^^^^^^^^^^^^^^
On Debian, Ubuntu, Linux Mint and related distributions, running ``apt-get install pdns-recursor`` as root will install the Recursor.

Enterprise Linux
^^^^^^^^^^^^^^^^
On Red Hat, CentOS and related distributions, ensure that `EPEL <https://fedoraproject.org/wiki/EPEL>`_ is available.
To install the PowerDNS Recursor, run ``yum install pdns-recursor`` as root.

FreeBSD
^^^^^^^
On FreeBSD the Recursor is available through the `ports system <http://www.freshports.org/dns/powerdns-recursor>`_.
Run ``pkg install powerdns-recursor`` as root to install.

To compile yourself from ports, run ``cd /usr/ports/dns/powerdns-recursor/ && make install clean``.

From Source
^^^^^^^^^^^
See :doc:`appendices/compiling` for instructions on how to build the PowerDNS Recursor from source.

Configuring the Recursor
------------------------
The configuration file is called ``recursor.conf`` and is located in the ``SYSCONFDIR`` defined at compile-time.
This is usually ``/etc/powerdns``, ``/etc/pdns``, ``/etc/pdns-recursor``, ``/usr/local/etc`` or similar.

Run ``pdns_recursor --no-config --config | grep config-dir`` to find this location on you installation.

The PowerDNS Recursor listens on the local loopback interface by default, this can be changed with the :ref:`setting-local-address` setting.

Now access will need to be granted to the Recursor.
The :ref:`setting-allow-from` setting lists the subnets that can communicate with the Recursor.

An example configuration is shown below.
Change this to match the local infrastructure.

.. code-block:: none

    local-address=192.0.2.25, 2001:DB8::1:25
    allow-from=192.0.2.0/24, 2001:DB8::1:/64

After a restart of the Recursor, it will answer queries on 192.0.2.25 and 2001:DB8::1:25, but only for queries with a source address in the 192.0.2.0/24 and 2001:DB8::1:/64 networks.

The recursor is now ready to be used.
For more options that can be set in ``recursor.conf`` see the :doc:`list of settings <settings>`.
Guidance on interaction with the Recursor is documented :doc:`here <running>`
If dynamic answer generation is needed or policies need to be applied to queries, the :doc:`scripting manual <lua-scripting/index>` will come in handy.

Using Ansible
-------------
The PowerDNS Recursor can also be installed and configured with `Ansible <https://ansible.com>`_.
There is a `role available <https://github.com/PowerDNS/pdns_recursor-ansible/>`_ from the PowerDNS authors.

