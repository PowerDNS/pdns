Managing DNSSEC Trust Anchors in the Lua Configuration
======================================================
The DNSSEC Trust Anchors and Negative Trust Anchors must be stored in the Lua Configuration file.
See the :doc:`../dnssec` for all information about DNSSEC in the PowerDNS Recursor.
This page only documents the Lua functions for DNSSEC configuration

.. function:: addTA(name, dscontent)

  .. versionadded:: 4.2.0

  Adds Trust Anchor to the list of DNSSEC anchors.

  :param str name: The name in the DNS tree from where this Trust Anchor should be used
  :param str dsrecord: The DS Record content associated with ``name``

.. function:: addDS(name, dscontent)

  .. deprecated:: 4.2.0
    Please use :func:`addTA` instead

  Adds a DS record (Trust Anchor) to the configuration

  :param str name: The name in the DNS tree from where this Trust Anchor should be used
  :param str dsrecord: The DS Record content associated with ``name``

.. function:: addNTA(name[, reason])

  Adds a Negative Trust Anchor for ``name`` to the configuration.
  Please read :ref:`ntas` for operational information on NTAs.

  :param str name: The name in the DNS tree from where this NTA should be used
  :param str reason: An optional comment to add to this NTA
