Lua2 Backend
============

* Native: Yes
* Master: Yes
* Slave: No
* Superslave: No
* Autoserial: No
* DNSSEC: Yes
* Disabled data: No
* Comments: No
* Module name: lua2
* Launch name: ``lua2``

This is a rewrite of existing Lua backend.
This backend is stub between your Lua script and PowerDNS authoritative server.
The backend uses AuthLua4 base class, and you can use same functions and types as in any other Lua script.

.. warning::
  Some of the function calls and configuration settings have been changed from original ``Luabackend``, please review this document carefully.

.. warning::
  All places which use DNS names now use DNSName class which cannot be compared directly to a string.
  To compare them against a string use either ``tostring(dnsname)`` or ``newDN(string)``.

.. warning::
  There is no API version 1.
  Use Luabackend if you need version 1.

API description (v2)
^^^^^^^^^^^^^^^^^^^^

``bool dns_dnssec``
~~~~~~~~~~~~~~~~~~~
If your script supports DNSSEC, set this to true.

``dns_lookup(qtype, qname, domain_id, ctx)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Perform lookup of given resource record name and type.

INPUT:
 - QType qtype - Type of queried resource record
 - DNSName qname - Name of queried resource record
 - int domain_id - ID of associated domain
 - table ctx - Query context table, contains ``source_address`` and ``real_source_address``.

OUTPUT:
 Expects a array which has tables with following keys:

 - DNSName name - resource record name (can also be string)
 - string type - type of resource record (can also be QType or valid integer)
 - string content - resource record content
 - int ttl - time to live for this resource record (default: configured value)
 - int domain_id - ID of associated domain (default: -1)
 - bool auth - Whether data is authoritative or not (default: true)
 - int last_modified - UNIX timestamp of last modification
 - int scope_mask - How many bytes of source IP netmask was used for this result

NOTES:
 Defaults are used for omitted keys.
 Return empty array if you have no results.
 The requested record type is unlikely to match what was asked from PowerDNS.
 This function is **required**.


``dns_list(target, domain_id)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
List all resource records for target.

INPUT:
 - DNSName target - Zone name to list
 - int domain_id - Associated domain ID

OUTPUT:
 Same as ``lookup`` function. Return false if not found or wanted.

NOTES:
 This function is **optional**.

.. _backends_lua2_dns_get_domaininfo:
 
``dns_get_domaininfo(domain)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Get domain information for given domain.

INPUT:
 - DNSName domain - Domain to get info for

OUTPUT:
 Return false if not supported or found, otherwise expects a table with keys:

 - string account - Associated account of this domain (default: <empty>)
 - string kind - Domain kind (NATIVE,MASTER,SLAVE) (default: NATIVE)
 - int id - Associated domain ID (default: -1)
 - int last_check - UNIX timestamp of last check from master (default: 0)
 - table of strings masters - Master servers for this domain (default: <empty>)
 - long notified_serial - Notified serial to slaves (default: 0)
 - long serial - Current domain serial

NOTES:
 This function is **optional**.
 Defaults are used for omitted keys.
 ``last_check`` is for automatic serial.
 ``masters``, ``account``, ``notified_serial`` are for master/slave interaction only.
 If this function is missing, it will revert into looking up SOA record for the given domain,
 and uses that, if found.

``dns_get_all_domains()``
~~~~~~~~~~~~~~~~~~~~~~~~~
Get domain information for all domains.

OUTPUT:
 Return false if not supported or found, otherwise return a table of string,
 domaininfo. See :ref:`dns_get_domaininfo() <backends_lua2_dns_get_domaininfo>`.

NOTES:
 This function is **optional**, except if you need master functionality.

``dns_get_domain_metadata(domain, kind)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Get metadata value(s) for given domain and metadata kind.

INPUT:
 - DNSName domain - Domain to get metadata for
 - string kind - What kind of metadata to return

OUTPUT:
 - array of strings. Or false if not supported or found.

NOTES:
 This function is **required** if ``dns_dnssec`` is true.

``dns_get_all_domain_metadata(domain)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Get all metadata for domain.

INPUT:
 - DNSName domain - Domain to get metadata for

OUTPUT:
 Table with metadata keys containing array of strings. Or false if not supported or found.

NOTES:
 This function is **optional**.

``dns_get_domain_keys(domain)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Get DNSSEC key(s) for the given domain. Content must be valid key record in format that PowerDNS understands.

INPUT:
 - DNSName domain - Domain to get key(s) for

OUTPUT:
 Return false if not found or supported, otherwise expects array of tables with keys:

 - int id - Key ID
 - int flags - Key flags
 - bool active - Is key active
 - string content - Key itself

NOTES:
 This function is **optional**. However, not implementing this means you cannot do live signing.

``dns_get_before_and_after_names_absolute(id, qname)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Calculate NSEC before/after value for the given qname for domain with id.

INPUT:
 - int id - Associated domain id
 - DNSName qname - DNS name to calculate

OUTPUT:
 Table with keys:

 - unhashed - DNSName of the unhashed relative to domain
 - before - (hashed) name of previous record relative to domain
 - after - (hashed) name of next record relative to domain

NOTES:
 Strings are promoted to DNSNames (you can also return DNSNames directly)
 This function is **required** if ``dns_dnssec`` is true.
 Hashing is required with NSEC3/5.
 ``before`` and ``after`` should wrap, so that after record of last record is apex record.
 You can use ``DNSName#canonCompare`` to sort records in correct order.

``dns_set_notified(id, serial)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Called after NOTIFY so that backend can store the notified serial.

INPUT:
 - int id - Associated domain id
 - long serial - Notified serial

NOTES:
 This function is **optional**. However, not implementing this can cause problems with master functionality.
