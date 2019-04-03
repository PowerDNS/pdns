jsonstat endpoint
=================

.. http:get:: /jsonstat

  Get statistics from recursor in JSON format.
  The ``Accept`` request header is ignored.
  This endpoint accepts a ``command`` and ``name`` query for different statistics:

  * ``get-query-ring``: Retrieve statistics from the query subsection. ``name`` can be ``servfail-queries`` or ``queries``.
  * ``get-remote-ring``: Retrieve statistics from the remotes subsection. ``name`` can be ``remotes``, ``bogus-remotes``, ``large-answer-remotes``, or ``timeouts``.

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-query-ring&name=servfail-queries HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-query-ring&name=queries HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=remotes HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=bogus-remotes HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=large-answer-remotes HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=get-remote-ring&name=timeouts HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

