Getting Started
===============
:program:`PowerDNS Recursor` can be installed on any modern unix-like system and is available in the software repositories for all major Linux distributions and BSDs.

Installation
------------
:program:`Recursor` is available for many platforms, instructions are provided here for several platforms.

.. note::
  As distribution provided package repositories are not always up-to-date, PowerDNS itself provides repositories for several :program:`Recursor` versions for different operating systems.
  Checkout `the repositories <https://repo.powerdns.com>`_ for more information.

Debian-based distributions
^^^^^^^^^^^^^^^^^^^^^^^^^^
On Debian, Ubuntu, Linux Mint and related distributions, running ``apt-get install pdns-recursor`` as root will install :program:`Recursor`.

Enterprise Linux
^^^^^^^^^^^^^^^^
On Red Hat, CentOS and related distributions, ensure that `EPEL <https://fedoraproject.org/wiki/EPEL>`_ is available.
To install :program:`Recursor`, run ``yum install pdns-recursor`` as root.

FreeBSD
^^^^^^^
On FreeBSD :program:`Recursor` is available through the `FreeBSD ports system <https://www.freshports.org/dns/powerdns-recursor>`_.
Run ``pkg install powerdns-recursor`` as root to install.

To compile yourself from ports, run ``cd /usr/ports/dns/powerdns-recursor/ && make install clean``.

OpenBSD
^^^^^^^
On OpenBSD, :program:`Recursor` is available through the `OpenBSD ports system <https://openports.se/net/powerdns_recursor>`_.
Run ``pkg_add powerdns-recursor`` as root to install.

macOS
^^^^^
On macOS :program:`Recursor` is available through `brew <https://brew.sh/>`_.
Run ``brew install pdnsrec`` to install.

Compiling From Source
^^^^^^^^^^^^^^^^^^^^^
See :doc:`appendices/compiling` for instructions on how to build :program:`Recursor` from source.

Configuring :program:`PowerDNS Recursor`
----------------------------------------
The configuration file is called ``recursor.conf`` or ``recursor.yml`` and is located in the ``SYSCONFDIR`` defined at compile-time.
This is usually ``/etc/powerdns``, ``/etc/pdns``, ``/etc/pdns-recursor``, ``/usr/local/etc`` or similar.
Since version 5.0 :program:`Recursor` also supports YAML style settings and since version 5.2 the old style settings format is deprecated.

Run ``pdns_recursor --config=default | grep config_dir`` to find this location on your installation.
Many packages provide a default configuration file that sets :ref:`setting-yaml-recursor.include_dir`.
Consider putting local configuration files into this directory, to make it clear which settings were locally modified.

:program:`Recursor` listens on the local loopback interface by default, this can be changed with the :ref:`setting-yaml-incoming.listen` setting.

Now access will need to be granted to the :program:`Recursor`.
The :ref:`setting-yaml-incoming.allow_from` setting lists the subnets that can communicate with :program:`Recursor`.

An example configuration is shown below.
Change this to match the local infrastructure.

.. code-block:: yaml

  incoming:
    listen: [192.0.2.25, '2001:DB8::1:25']
    allow_from: [192.0.2.0/24, '2001:DB8::1:/64']

After a restart of :program:`Recursor`, it will answer queries on 192.0.2.25 and 2001:DB8::1:25, but only for queries with a source address in the 192.0.2.0/24 and 2001:DB8::1:/64 networks.

:program:`Recursor` is now ready to be used.
For more options that can be set in the recursor configuration see the :doc:`PowerDNS Recursor Settings<yamlsettings>`.
Guidance on interaction with :program:`Recursor` is documented in :doc:`Operating PowerDNS Recursor<running>`.
If dynamic answer generation is needed or policies need to be applied to queries, the :doc:`Scripting PowerDNS Recursor <lua-scripting/index>` will come in handy.

Using Ansible
-------------
:program:`PowerDNS Recursor` can also be installed and configured with `Ansible <https://ansible.com>`_.
There is a `role available <https://github.com/PowerDNS/pdns_recursor-ansible/>`_ from the PowerDNS authors.

