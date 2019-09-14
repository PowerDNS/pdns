Key Value Store functions and objects
=====================================

These are all the functions, objects and methods related to the CDB and LMDB key value stores.

As of 1.4.0, the CDB and LMDB code is considered experimental.

A lookup into a key value store can be done via the :func:`KeyValueStoreLookupRule` rule or
the :func:`KeyValueStoreLookupAction` action, using the usual selectors to match the incoming
queries for which the lookup should be done.

The first step is to get a :ref:`KeyValueStore` object via one of the following functions:

 * :func:`newCDBKVStore` for a CDB database ;
 * :func:`newLMDBKVStore` for a LMDB one.

Then the key used for the lookup can be selected via one of the following functions:

 * the exact qname with :func:`KeyValueLookupKeyQName` ;
 * a suffix match via :func:`KeyValueLookupKeySuffix`, meaning that several lookups will be done, removing one label from the qname at a time, until a match has been found or there is no label left ;
 * the source IP with :func:`KeyValueLookupKeySourceIP` ;
 * the value of an existing tag with :func:`KeyValueLookupKeyTag`.

For example, to do a suffix-based lookup into a LMDB KVS database, the following rule can be used:

.. code-block:: lua

  > kvs = newLMDBKVStore('/path/to/lmdb/database', 'database name')
  > addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySuffix(), 'kvs-suffix-result'))

For a query whose qname is "sub.domain.powerdns.com.", and for which only the "\\8powerdns\\3com\\0" key exists in the database,
this would result in the following lookups:

 * \\3sub\\6domain\\8powerdns\\3com\\0
 * \\6domain\\8powerdns\\3com\\0
 * \\8powerdns\\3com\\0

Then a match is found for the last key, and the corresponding value is stored into the 'kvs-suffix-result' tag. This tag can now be used in subsequent rules to take an action based on the result of the lookup.

.. code-block:: lua

 > addAction(TagRule('kvs-suffix-result', 'this is the value obtained from the lookup'), SpoofAction('2001:db8::1'))

If the value found in the LMDB database for the key '\\8powerdns\\3com\\0' was 'this is the value obtained from the lookup', then the query is immediately answered with a AAAA record.


.. class:: KeyValueStore

  .. versionadded:: 1.4.0

  Represents a Key Value Store

  .. method:: KeyValueStore:lookup(key [, wireFormat])

    Does a lookup into the corresponding key value store, and return the result as a string.
    The key can be a :class:`ComboAddress` obtained via the :func:`newCA`, a :class:`DNSName` obtained via the :func:`newDNSName` function, or a raw string.

    :param ComboAddress, DNSName or string key: The key to look up
    :param bool wireFormat: If the key is DNSName, whether to use to do the lookup in wire format (default) or in plain text

  .. method:: KeyValueStore:lookupSuffix(key [, minLabels [, wireFormat]])

    Does a suffix-based lookup into the corresponding key value store, and return the result as a string.
    The key should be a :class:`DNSName` object obtained via the :func:`newDNSName` function, and several lookups will be done, removing one label from the name at a time until a match has been found or there is no label left.
    If ``minLabels`` is set to a value larger than 0 the lookup will only be done as long as there is at least ``minLabels`` remaining. For example if the initial domain is "sub.powerdns.com." and ``minLabels`` is set to 2, lookups will only be done for "sub.powerdns.com." and "powerdns.com.".

    :param DNSName key: The name to look up
    :param int minLabels: The minimum number of labels to do a lookup for. Default is 0 which means unlimited
    :param bool wireFormat: Whether to do the lookup in wire format (default) or in plain text

  .. method:: KeyValueStore:reload()

    Reload the database if this is supported by the underlying store. As of 1.4.0, only CDB stores can be reloaded, and this method is a no-op for LMDB stores.


.. function:: KeyValueLookupKeyQName([wireFormat]) -> KeyValueLookupKey

  .. versionadded:: 1.4.0

  Return a new KeyValueLookupKey object that, when passed to :func:`KeyValueStoreLookupAction` or :func:`KeyValueStoreLookupRule`, will return the qname of the query in DNS wire format.

  :param bool wireFormat: Whether to do the lookup in wire format (default) or in plain text

.. function:: KeyValueLookupKeySourceIP() -> KeyValueLookupKey

  .. versionadded:: 1.4.0

  Return a new KeyValueLookupKey object that, when passed to :func:`KeyValueStoreLookupAction` or :func:`KeyValueStoreLookupRule`, will return the source IP of the client in network byte-order.

.. function:: KeyValueLookupKeySuffix([minLabels [, wireFormat]]) -> KeyValueLookupKey

  .. versionadded:: 1.4.0

  Return a new KeyValueLookupKey object that, when passed to :func:`KeyValueStoreLookupAction` or :func:`KeyValueStoreLookupRule`, will return a vector of keys based on the labels of the qname in DNS wire format or plain text.
  For example if the qname is sub.domain.powerdns.com. the following keys will be returned:

   * \\3sub\\6domain\\8powerdns\\3com\\0
   * \\6domain\\8powerdns\\3com\\0
   * \\8powerdns\\3com\\0
   * \\3com\\0
   * \\0

  If ``minLabels`` is set to a value larger than 0 the lookup will only be done as long as there is at least ``minLabels`` remaining. Taking back our previous example, it means only the following keys will be returned if ``minLabels`` is set to 2;

   * \\3sub\\6domain\\8powerdns\\3com\\0
   * \\6domain\\8powerdns\\3com\\0
   * \\8powerdns\\3com\\0

  :param int minLabels: The minimum number of labels to do a lookup for. Default is 0 which means unlimited
  :param bool wireFormat: Whether to do the lookup in wire format (default) or in plain text

.. function:: KeyValueLookupKeyTag() -> KeyValueLookupKey

  .. versionadded:: 1.4.0

  Return a new KeyValueLookupKey object that, when passed to :func:`KeyValueStoreLookupAction`, will return the value of the corresponding tag for this query, if it exists.

.. function:: newCDBKVStore(filename, refreshDelay) -> KeyValueStore

  .. versionadded:: 1.4.0

  Return a new KeyValueStore object associated to the corresponding CDB database. The modification time
  of the CDB file will be checked every 'refrehDelay' second and the database re-opened if needed.

  :param string filename: The path to an existing CDB database
  :param int refreshDelays: The delay in seconds between two checks of the database modification time. 0 means disabled

.. function:: newLMDBKVStore(filename, dbName) -> KeyValueStore

  .. versionadded:: 1.4.0

  Return a new KeyValueStore object associated to the corresponding LMDB database. The database must have been created
  with the ``MDB_NOSUBDIR`` flag.

  :param string filename: The path to an existing LMDB database created with ``MDB_NOSUBDIR``
  :param string dbName: The name of the database to use
