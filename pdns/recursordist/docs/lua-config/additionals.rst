.. _additionals:

Adding Additional Records to Results
====================================
Starting with version 4.7.0, the PowerDNS Recursor has the ability to add additional records to query results.

This allows clients to learn useful information without having to do an extra query.
Examples of useful information are the related ``A`` and ``AAAA`` records to a query for an ``MX`` record:

::

  ;; ANSWER SECTION:
  example.net.              86362   IN      MX      20 mx2.example.net.
  example.net.              86362   IN      MX      10 mx1.example.net.

  ;; ADDITIONAL SECTION:
  mx1.example.net.          86368   IN      A       192.168.1.2
  mx2.example.net.          86400   IN      A       192.168.1.3
  mx1.example.net.          86372   IN      AAAA    2001:db8::1
  mx2.example.net.          86374   IN      AAAA    2001:db8::2

The default is that the Recursor never adds additional records to an answer it sends to the client.
The default behavior can be changed by using the :func:`addAllowedAdditionalQType` function in the :ref:`setting-yaml-recursor.lua_config_file`.
For each query type allowing additional record processing the Recursor has code to determine the target name to add.
The target qtypes to add are configurable as is the mode, specifying how to retrieve the records to add.

An example of a configuration:

.. code-block:: Lua

  addAllowedAdditionalQType(pdns.MX, {pdns.A, pdns.AAAA})
  addAllowedAdditionalQType(pdns.NAPTR, {pdns.A, pdns.AAAA, pdns.SRV}, {mode=pdns.AdditionalMode.ResolveImmediately})

The first line specifies that additional records should be added to the results of ``MX`` queries using the default mode.
The qtype of the records to be added are ``A`` and ``AAAA``.
The default mode is ``pdns.AdditionalMode.CacheOnlyRequireAuth``; this mode will only look in the record cache.

The second line specifies that three record types should be added to ``NAPTR`` answers.
If needed, the Recursor will do an active resolve to retrieve these records.

Note that with record types such as ``NAPTR`` which can return records such as ``SRV``, which may themselves return additional 
``A`` or ``AAAA`` records, the above example would not be sufficient to return those additional ``A`` and/or ``AAAA`` records. 
In such a case, you  would need to add an additional line to tell the recursor to fetch the additional records for the ``SRV`` 
qtype as well. An example configuration for this case is shown below:

.. code-block:: Lua

  addAllowedAdditionalQType(pdns.NAPTR, {pdns.A, pdns.AAAA, pdns.SRV}, {mode=pdns.AdditionalMode.ResolveImmediately})
  addAllowedAdditionalQType(pdns.SRV, {pdns.A, pdns.AAAA}, {mode=pdns.AdditionalMode.ResolveImmediately})

The modes available are:

``pdns.AdditionalMode.Ignore``
  Do not do any additional processing for this qtype.
  This is equivalent to not calling :func:`addAllowedAdditionalQType` for the qtype.
``pdns.AdditionalMode.CacheOnly``
  Look in the record cache for available records.
  Allow non-authoritative (learned from additional sections received from authoritative servers) records to be added.
``pdns.AdditionalMode.CacheOnlyRequireAuth``
  Look in the record cache for available records.
  Only authoritative records will be added. These are records received from the nameservers for the specific domain.
``pdns.AdditionalMode.ResolveImmediately``
  Add records from the record cache (including DNSSEC records if relevant).
  If no record is found in the record cache, actively try to resolve the target name/qtype.
  This will delay the answer to the client.
``pdns.AdditionalMode.ResolveDeferred``
  Add records from the record cache (including DNSSEC records if relevant).
  If no record is found in the record cache and the negative cache also has no entry, schedule a task to resolve the target name/qtype.
  The next time the query is processed, the cache might hold the relevant information.
  If a task is pushed, the answer that triggered it will be marked as variable and consequently not stored into the packet cache.

If an additional record is not available at that time the query is stored into the packet cache the answer packet stored in the packet cache will not contain the additional record.
Clients repeating the same question will get an answer from the packet cache if the question is still in the packet cache.
These answers do not have the additional record, even if the record cache has learned it in the meantime .
Clients will only see the additional record once the packet cache entry expires and the record cache is consulted again.
The ``pdns.AdditionalMode.ResolveImmediately`` mode will not have this issue, at the cost of delaying the first query to resolve the additional records needed.
The ``pdns.AdditionalMode.ResolveDeferred`` mode will only store answers in the packet cache if it determines that no deferred tasks are needed, i.e. either a positive or negative answer for potential additional records is available.
If the additional records for an answer have low TTLs compared to the records in the answer section, tasks will be pushed often.
Until all tasks for the answer have completed the packet cache will not contain the answer, making the packet cache less effective for this specific answer.

Configuring additional record processing
----------------------------------------

The following function is available to configure additional record processing.
Reloading the Lua configuration will replace the current configuration with the new one.
Calling  :func:`addAllowedAdditionalQType` multiple times with a specific qtype will replace previous calls with the same qtype.

.. function:: addAllowedAdditionalQType(qtype, targets [, options ]))

  .. versionadded:: 4.7.0
  .. versionadded:: 5.1.0 Alternative equivalent YAML setting: :ref:`setting-yaml-recursor.allowed_additional_qtypes`.

  Allow additional processing for ``qtype``.

  :param int qtype:  the qtype number to enable additional record processing for. Supported are: ``pdns.MX``, ``pdns.SRV``, ``pdns.SVCB``, ``pdns.HTTPS`` and ``pdns.NAPTR``.
  :param targets: the target qtypes to look for when adding the additionals. For example ``{pdns.A, pdns.AAAA}``.
  :type targets: list of qtype numbers
  :param table options: a table of options. Currently the only option is ``mode`` having an integer value. For the available modes, see above. If no mode is specified, the default ``pdns.AdditionalMode.CacheOnlyRequireAuth`` mode is used.

