Installing PowerDNS
===================

Installation of the PowerDNS Authoritative server on UNIX systems can be
done in several ways:

-  Binary packages provided by your distribution
-  Binary packages provided by PowerDNS on
   `repo.powerdns.com <https://repo.powerdns.com>`__

Binary Packages
---------------

Debian-based Systems
~~~~~~~~~~~~~~~~~~~~

PowerDNS Authoritative Server is available through the
`apt <https://packages.debian.org/pdns-server>`__ system.

::

    # apt-get install pdns-server

Debian splits the backends into `several different
packages <https://packages.debian.org/pdns-backend>`__, install the
required backend as follows:

::

    # apt-get install pdns-backend-$backend

Redhat-based Systems
~~~~~~~~~~~~~~~~~~~~

On RedHat based system there are 2 options to install PowerDNS, from
`EPEL <https://fedoraproject.org/wiki/EPEL>`__, the `repository from
Kees Monshouwer <https://www.monshouwer.eu/download/3rd_party/pdns/>`__
or from `the PowerDNS repositories <https://repo.powerdns.com>`__:

Add either to your list of repositories and install PowerDNS by issuing:

::

    # yum install pdns

The different backends can be installed using

::

    # yum install pdns-backend-$backend

FreeBSD
~~~~~~~

PowerDNS Authoritative Server is available through the
`ports <http://www.freshports.org/dns/powerdns/>`__ system:

For the package:

::

    # pkg install dns/powerdns

To have your system build the port:

::

    cd /usr/ports/dns/powerdns/ && make install clean

Mac OS X
~~~~~~~~

PowerDNS Authoritative Server is available through Homebrew:

::

    $ brew install pdns

After installation
------------------

Once installed, :doc:`guides/basic-database` using MySQL or start :doc:`migrating <migration>` your data.
