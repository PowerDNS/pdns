EDNS Client Subnet Zero Scope
==================================

As described in :doc:`Passing the source address to the backend <passing-source-address>`, :program:`dnsdist` can add an ``EDNS`` Client Subnet option to an incoming query to provide the downstream server with the address of the client talking to it. The downstream server can then potentially use this knowledge to reply with a response that has been tailored for this specific client, and should not be served to any other client. By default :program:`dnsdist` ensures that such a response is only served to intended client from its internal packet cache, including the added ``EDNS`` Client Subnet option in the data that is hashed to compute the cache key. This is the safest option, but is not optimal because some responses were not actually tied to a specific client subnet and could have been used for all of them. The downstream server can signal this by setting the scope in the ``EDNS`` Client Subnet option included in the response.

This is where the zero-scope feature comes to play, allowing :program:`dnsdist` to parse and detect that a response sent by the backend has a scope value set to ``0``, indicating that the answer is not specific to a given client subnet and can be used for all of them. :program:`dnsdist` will then store the answer in its packet cache using the initial query as the key, before the ``EDNS`` Client Subnet option has been added.

The second step needed for that feature to work properly is for :program:`dnsdist` to look up twice into the packet cache when a query arrives, first without and then with the ``EDNS`` Client Subnet option. That way, when most of the responses sent by a backend are not specific and can be served to all clients, :program:`dnsdist` will still be able to have a great cache-hit ratio for non specific entries.

This feature is enabled when:

* ``disableZeroScope=true`` is not set on :func:`newServer` (the default is ``false``)
* and ``parseECS=true`` is set on :func:`newPacketCache` (which is not the default).
