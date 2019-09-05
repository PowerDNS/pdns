Prometheus Data Endpoint
========================

.. versionadded:: 4.3.0

.. http:get:: /metrics

    Get statistics from Recursor in `Prometheus <https://prometheus.io>`_ format. Uses :ref:`setting-webserver-password` and returned list can be controlled with :ref:`setting-stats-api-blacklist`

  **Example request**:
   .. sourcecode:: bash

    curl -i -u=#:webpassword http://127.0.0.1:8081/metrics

  **Example response**:
   .. sourcecode:: http

    HTTP/1.1 200 OK
    Connection: close
    Content-Length: 19203
    Content-Type: text/plain
    Server: PowerDNS/0.0.16480.0.g876dd46192

    # HELP pdns_recursor_all_outqueries Number of outgoing UDP queries since starting
    # TYPE pdns_recursor_all_outqueries counter
    pdns_recursor_all_outqueries 20
    # HELP pdns_recursor_answers_slow Number of queries answered after 1 second
    # TYPE pdns_recursor_answers_slow counter
    pdns_recursor_answers_slow 0
    # HELP pdns_recursor_answers0_1 Number of queries answered within 1 millisecond
    # TYPE pdns_recursor_answers0_1 counter
    pdns_recursor_answers0_1 0
    # HELP pdns_recursor_answers1_10 Number of queries answered within 10 milliseconds
    # TYPE pdns_recursor_answers1_10 counter

    ...

