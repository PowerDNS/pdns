Failure logging endpoint
========================
.. note::

  Not yet implemented

.. http:put:: /api/v1/servers/:server_id/failure

  Configure query failure logging.

  :query server_id: The name of the server

  **Example client body:**

  .. code-block:: json

    {
      "top-domains": 100,
      "domains": ".*\\.example\\.com$"
    }

  :property int top-domains: Number of top resolved domains that are automatically monitored for failures.
  :property string domains: A Regex of domains that are additionally monitored for resolve failures.

.. http:get:: /api/v1/servers/:server_id/failure

  .. note::

    Not yet implemented

  Retrieve query failure logging and current config.

  **Example response body:**

  .. code-block:: json

    {
      "top-domains": 100,
      "domains": ".*\\.example\\.com$",
      "log": [
        {
          "first_occurred": 1234567890,
          "domain": "www.example.net",
          "qtype": "A",
          "failure": "dnssec-parent-validation-failed",
          "failed_parent": "example.com",
          "details": "foo bar",
          "queried_servers": [
             {
               "name": "ns1.example.net",
               "address": "192.0.2.53"
             }
          ]
        }
      ]
    }

  :property string failed_parent: The parent domain, this is generally OPTIONAL.
  :property string failure_code: Reason of failure.

    -  ``dnssec-validation-failed``: DNSSEC Validation failed for this domain.
    -  ``dnssec-parent-validation-failed``: DNSSEC Validation failed for one of the parent domains. Response MUST contain ``failed_parent``.
    -  ``nxdomain``: This domain was not present on the authoritative nameservers.
    -  ``nodata``: ???
    -  ``all-servers-unreachable``: All auth nameservers that have been tried did not respond.
    -  ``parent-unresolvable``: Response MUST contain ``failed_parent``.
    -  ``refused``: All auth nameservers that have been tried responded with REFUSED.
    -  ``servfail``: All auth nameservers that have been tried responded with SERVFAIL.

  :property string domain: The domain queried
