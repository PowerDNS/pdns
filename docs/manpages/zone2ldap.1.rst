zone2ldap
=========

Synopsis
--------

:program:`zone2ldap` <INPUT_OPTION>... [OPTION]...

Description
-----------

:program:`zone2ldap` is a program that converts BIND zonefiles to ldif format
which can inserted to an LDAP server.

INPUT Options
-------------

.. option:: --named-conf=<PATH>

   Read *PATH* to get the BIND configuration

.. option:: --zone=<PATH>

   Parse only the zone file at *PATH*.
   Conflicts with ``--named-conf`` parameter.

.. option:: --zone-name=<NAME>

   When parsing a single zone without $ORIGIN statement, set *ZONE* as the zone name.

Options
-------

.. option:: --help

   Show summary of options.

.. option:: --basedn=<DN>

   Base DN to store objects below

.. option:: --dnsttl

   Add dnsttl attribute to every entry

.. option:: --layout=<LAYOUT>

   How to arrange entries in the directory ("simple" or "tree")

.. option:: --resume

   Continue after errors

.. option:: --verbose

   Verbose comments on operation

See also
--------

pdns_server(1)
