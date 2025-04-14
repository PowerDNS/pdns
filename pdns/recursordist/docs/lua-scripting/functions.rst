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

   Spawn a new thread running the supplied Lua script in a newly created Lua context.

   :param str script: The pathname of the Lua script to run.

.. note::
     The :func:`putIntoRecordCache` and :func:`getRecordCacheRecords` functions are experimental, their functionality might change in upcoming releases.

.. function:: putIntoRecordCache(dump) -> int

   .. versionadded:: 5.2.0

   Load a record cache dump into the record cache.

   :param str dump: The data in the proprietary format produced by :func:`getRecordCacheRecords`).
   :returns: The number of records inserted into the record cache.

   Some record sets might be skipped, for example when they are already present in the record cache or contain specific information not supported yet by this function.
   If the :program:`Recursor` determines the version of the data is not compatible, it will skip loading and log an error.
   In that case 0 is returned.

.. function:: getRecordCacheRecords(perShard, maxSize) -> str, int

   .. versionadded:: 5.2.0

   Get a record cache dump in proprietary format.

   :param int perShard: The maximum number of record sets to retrieve per shard. Zero is unlimited.
   :param int maxSize: The maximum size of the dump. Zero is unlimited.

   :return: A string representing the record sets and an integer specifying how many record sets were retrieved

   This function will scan the most recently used record sets of each shard, picking at most ``perShard`` record sets per shard and adding them to the result.
   If adding a record set's data to the result would make the result size exceed ``maxSize``, the remainder of the current shard and further remaining shards are skipped.
   The format of the string produced is proprietary.
   The string contains meta information, so the :program:`Recursor` calling :func:`putIntoRecordCache` can check if the data format is compatible.

   Note that setting both limits to zero can produce very large strings. It is wise to set at least one of the limits.
   Additionally, setting ``maxSize`` to zero can lead to less efficient memory management while producing the dump.

.. function:: getConfigDirAndName() -> str, str

   .. versionadded:: 5.2.3

   Get the configuration directory and the instance name.
   These two values correspond to the :ref:`setting-yaml-recursor.config_dir` and :ref:`setting-yaml-recursor.config_name` settings.
