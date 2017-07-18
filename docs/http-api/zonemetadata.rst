Zone Metadata
=============

.. versionadded:: 4.1.0.

.. json:object:: Metadata

  Represents zone metadata :doc:`../domainmetadata`

  :property string kind: Name of the metadata
  :property [string] metadata: Array with all values for this metadata kind.

  Clients MUST NOT modify ``NSEC3PARAM``, ``NSEC3NARROW``, ``PRESIGNED`` and ``LUA-AXFR-SCRIPT`` through this interface.
  The server rejects updates to these metadata.
  Modifications to custom metadata kinds starting with ``X-`` is allowed as well.
