Caching Responses
=================

:program:`dnsdist` implements a simple but effective packet cache, not enabled by default.
It is enabled per-pool, but the same cache can be shared between several pools.
The first step is to define a cache with :func:`newPacketCache`, then to assign that cache to the chosen pool, the default one being represented by the empty string::

  pc = newPacketCache(10000, {maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=false})
  getPool(""):setCache(pc)

 + The first parameter (10000) is the maximum number of entries stored in the cache, and is the only one required. All the other parameters are optional and in seconds, except the last one which is a boolean.

+ The second one (86400) is the maximum lifetime of an entry in the cache.

+ The third one (0) is the minimum TTL an entry should have to be considered for insertion in the cache.

+ The fourth one (60) is the TTL used for a Server Failure or a Refused response.

+ The fifth one (60) is the TTL that will be used when a stale cache entry is returned.

+ The sixth one is a boolean that when set to true, avoids reducing the TTL of cached entries.

For performance reasons the cache will pre-allocate buckets based on the maximum number of entries, so be careful to set the first parameter to a reasonable value.
Something along the lines of a dozen bytes per pre-allocated entry can be expected on 64-bit.
That does not mean that the memory is completely allocated up-front, the final memory usage depending mostly on the size of cached responses and therefore varying during the cache's lifetime.
Assuming an average response size of 512 bytes, a cache size of 10000000 entries on a 64-bit host with 8GB of dedicated RAM would be a safe choice.

The :func:`setStaleCacheEntriesTTL` directive can be used to allow dnsdist to use expired entries from the cache when no backend is available.
Only entries that have expired for less than n seconds will be used, and the returned TTL can be set when creating a new cache with :func:`newPacketCache`.

A reference to the cache affected to a specific pool can be retrieved with::

  getPool("poolname"):getCache()

And removed with::

  getPool("poolname"):unsetCache()

Cache usage stats (hits, misses, deferred inserts and lookups, collisions) can be displayed by using the :meth:`PacketCache:printStats` method::

  getPool("poolname"):getCache():printStats()

The same values can also be returned as a Lua table, which is easier to work with from a script, using the :meth:`PacketCache:getStats` method.

Expired cached entries can be removed from a cache using the :meth:`PacketCache:purgeExpired` method, which will remove expired entries from the cache until at most n entries remain in the cache.
For example, to remove all expired entries::

  getPool("poolname"):getCache():purgeExpired(0)

Specific entries can also be removed using the :meth:`PacketCache:expungeByName` method::

  getPool("poolname"):getCache():expungeByName(newDNSName("powerdns.com"), DNSQType.A)

.. versionchanged:: 1.4.0
  Before 1.4.0, the QTypes were in the ``dnsdist`` namespace. Use ``dnsdist.A`` in these versions.

Finally, the :meth:`PacketCache:expunge` method will remove all entries until at most n entries remain in the cache::

  getPool("poolname"):getCache():expunge(0)
