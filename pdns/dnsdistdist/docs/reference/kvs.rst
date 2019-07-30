Key Value Store functions and objects
=====================================

These are all the functions, objects and methods related to the CDB and LMDB key value stores.

A lookup into a key value store can be done via the :func:`KeyValueStoreLookupAction` action,
using the usual selectors to match the incoming queries for which the lookup should be done.

The first step is to get a :ref:`KeyValueStore` object via one of the following functions:

 * :func:`newCDBKVStore` for a CDB database ;
 * :func:`newLMDBKVStore` for a LMDB one.

Then the key used for the lookup can be selected via one of the following functions:

 * the exact qname with :func:`KeyValueLookupKeyQName` ;
 * a suffix match via :func:`KeyValueLookupKeySuffix`, meaning that several lookups will be done, removing one label from the qname at a time, until a match has been found or there is no label left ;
 * the source IP with :func:`KeyValueLookupKeySourceIP` ;
 * the value of an existing tag with :func:`KeyValueLookupKeyTag`.

For example, to do a suffix-based lookup into a LMDB KVS database, the following rule can be used:

  > kvs = newLMDBKVStore('/path/to/lmdb/database', 'database name')
  > addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySuffix(), 'kvs-suffix-result'))

For a query whose qname is "sub.domain.powerdns.com.", and for which only the "\8powerdns\3com\0" key exists in the database,
this would result in the following lookups:

 * \3sub\6domain\8powerdns\3com\0
 * \6domain\8powerdns\3com\0
 * \8powerdns\3com\0

Then a match is found for the last key, and the corresponding value is stored into the 'kvs-suffix-result' tag. This tag can now be used in subsequent rules to take an action based on the result of the lookup.

 > addAction(TagRule('kvs-suffix-result', 'this is the value obtained from the lookup'), SpoofAction('2001:db8::1'))

If the value found in the LMDB database for the key '\8powerdns\3com\0' was 'this is the value obtained from the lookup', then the query is immediately answered with a AAAA record.


.. class:: KeyValueStore

  .. versionadded:: 1.5.0

  Represents a Key Value Store

  .. method:: KeyValueStore:lookup(key)

    Does a lookup into the corresponding key value store, and return the result as a string.
    The key is first parsed as a network address, and if that fails into a DNS name. If that also fails the raw string is used for the lookup.

    :param string key: The key to look up

  .. method:: KeyValueStore:lookupSuffix(key)

    Does a suffix-based lookup into the corresponding key value store, and return the result as a string.
    The key is parsed as a DNS name, and several lookups will be done, removing one label from the name at a time until a match has been found or there is no label left.

    :param string key: The name to look up

  .. method:: KeyValueStore:reload()

    Reload the database if this is supported by the underlying store. As of 1.5.0, only CDB stores can be reloaded, and this method is a no-op for LMDB stores.


.. function:: KeyValueLookupKeyQName() -> KeyValueLookupKey

  .. versionadded:: 1.5.0

  Return a new KeyValueLookupKey object that, when passed to :func:`KeyValueStoreLookupAction`, will return the qname of the query in DNS wire format.

.. function:: KeyValueLookupKeySourceIP() -> KeyValueLookupKey

  .. versionadded:: 1.5.0

  Return a new KeyValueLookupKey object that, when passed to :func:`KeyValueStoreLookupAction`, will return the source IP of the client in network byte-order.

.. function:: KeyValueLookupKeySuffix() -> KeyValueLookupKey

  .. versionadded:: 1.5.0

  Return a new KeyValueLookupKey object that, when passed to :func:`KeyValueStoreLookupAction`, will return a vector of keys based on the labels of the qname in DNS wire format.
  For example if the qname is sub.domain.powerdns.com. the following keys will be returned:

   * \3sub\6domain\8powerdns\3com\0
   * \6domain\8powerdns\3com\0
   * \8powerdns\3com\0
   * \3com\0
   * \0

.. function:: KeyValueLookupKeyTag() -> KeyValueLookupKey

  .. versionadded:: 1.5.0

  Return a new KeyValueLookupKey object that, when passed to :func:`KeyValueStoreLookupAction`, will return the value of the corresponding tag for this query, if it exists.

.. function:: newCDBKVStore(filename, refreshDelay) -> KeyValueStore

  .. versionadded:: 1.5.0

  Return a new KeyValueStore object associated to the corresponding CDB database. The modification time
  of the CDB file will be checked every 'refrehDelay' second and the database re-opened if needed.

  :param string filename: The path to an existing CDB database
  :param int refreshDelays: The delay in seconds between two checks of the database modification time. 0 means disabled

.. function:: newLMDBKVStore(filename, dbName) -> KeyValueStore

  .. versionadded:: 1.5.0

  Return a new KeyValueStore object associated to the corresponding LMDB database. The database must have been created
  with the ``MDB_NOSUBDIR`` flag.

  :param string filename: The path to an existing LMDB database created with ``MDB_NOSUBDIR``
  :param string dbName: The name of the database to use
