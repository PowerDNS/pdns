Query Tracing endpoint
======================

.. note::

  Not yet implemented

.. http:put:: /api/v1/servers/:server_id/trace

  Configure query tracing.

  :query server_id: The name of the server

  **Client body:**

  .. code-block:: json

    {
      "domains": "<regex_string>"
    }

  Set ``domains`` to ``null`` to turn off tracing.


.. http:get:: /api/v1/servers/:server_id/trace

  Retrieve query tracing log and current config.

  :query server_id: The name of the server

  **Response Body:**

  .. code-block:: json

    {
      "domains": "<Regex>",
      "log": [
        "<log_line>"
      ]
    }
