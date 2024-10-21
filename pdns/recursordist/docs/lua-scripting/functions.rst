Other functions
===============

These are some functions that don't really have a place in one of the other categories.

.. function:: getregisteredname(name) -> str

  Returns the shortest domain name based on Mozilla's Public Suffix List.
  In general it will tell you the 'registered domain' for a given name.

  For example ``getregisteredname('www.powerdns.com')`` returns "powerdns.com"

  :param str name: The name to check for.

.. function:: getRecursorThreadId() -> int

  returns an unsigned integer identifying the thread handling the current request.

.. function:: pdnsrandom([upper_bound])

  Get a random number.

  :param int upper_bound: The upper bound. You will get a random number below this upper bound.

.. function:: spawnThread(script)

   .. versionadded:: 5.2.0

   Spawn a thread.

   :param str script: The pathname of the Lua script to run.

.. function:: putIntoRecordCache(dump) -> int

   .. versionadded:: 5.2.0

   Put a record cache dump into the record cache.

   :param str dump: The data in the proprietary format produced by :func:`getRecordCacheRecords`).
   :returns: The number of records inserted into the record cache.

   Some records might be skipped, for example when they are already present in the record cache or contain specific information not supported yet by this function.
   If the :program:`Recursor` determines the version of the data is not compatible, it will skip loading and log an error.

.. function:: getRecordCacheRecords(perShard, maxSize) ->str

   .. versionadded:: 5.2.0

   Get a record cache dump in proprietary format.

   :param int perShard: The maximum number of records to produce per shard.
   :param int maxSize: The maximum size of the dump.

   :return: A string representing the records.

   This function will scan the most recently used records of each shard, picking at most ``perShard`` records per shard and adding them to the result.
   If adding a record's data to the result would make the result size exceed ``maxSize``, the remainder of the current shard and further remaining shards are skipped.
   The format of the string produced is proprietary.
   The string contains meta information, so the :program:`Recursor` calling :func:`putIntoRecordCache` can check if the data format is compatible.
