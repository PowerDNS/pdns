Exporting statistics via Carbon
===============================

Setting up a carbon export
--------------------------

To emit metrics to Graphite, or any other software supporting the Carbon protocol, use::

  carbonServer('ip-address-of-carbon-server', 'ourname', 30, 'dnsdist', 'main')

Where ``ourname`` can be used to override your hostname, and ``30`` is the reporting interval in seconds. ``dnsdist`` and ``main`` are used as namespace and instance variables. For querycount statistics these two variables are currently ignored. The last four arguments can be omitted.
The latest version of `PowerDNS Metronome <https://github.com/ahupowerdns/metronome>`_ comes with attractive graphs for dnsdist by default.

Query counters
--------------

In addition to other metrics, it is possible to send per-records statistics of the amount of queries by using :func:`setQueryCount`. With query counting enabled, dnsdist will increase a counter for every unique record or the behaviour you define in a custom Lua function by setting :func:`setQueryCountFilter`. This filter can decide whether to keep count on a query at all or rewrite for which query the counter will be increased. An example of a QueryCountFilter would be:

.. code-block:: lua

  function filter(dq)
    qname = dq.qname:toString()

    -- don't count PTRs at all
    if(qname:match('in%-addr.arpa$')) then
      return false, ""
    end

    -- count these queries as if they were queried without leading www.
    if(qname:match('^www.')) then
      qname = qname:gsub('^www.', '')
    end

    -- count queries by default
    return true, qname
  end

  setQueryCountFilter(filter)

Valid return values for ``QueryCountFilter`` functions are:

- true: count the specified query
- false: don't count the query

Note that the query counters are buffered and flushed each time statistics are sent to the carbon server. The current content of the buffer can be inspected with ::func:`getQueryCounters`. If you decide to enable query counting without :func:`carbonServer`, make sure you implement clearing the log from ``maintenance()`` by issuing :func:`clearQueryCounters`.
