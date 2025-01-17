.. raw:: latex

    \setcounter{secnumdepth}{-1}

YAML support structures
=======================

.. _yaml-settings-ResponseConfig:

ResponseConfig
--------------

- **set_aa**: Boolean
- **set_ad**: Boolean
- **set_ra**: Boolean
- **ttl**: Unsigned integer

.. _yaml-settings-SOAParams:

SOAParams
---------

- **serial**: Unsigned integer
- **refresh**: Unsigned integer
- **retry**: Unsigned integer
- **expire**: Unsigned integer
- **minimum**: Unsigned integer

.. _yaml-settings-SVCRecordAdditionalParams:

SVCRecordAdditionalParams
-------------------------

- **key**: Unsigned integer
- **value**: String

.. _yaml-settings-SVCRecordParameters:

SVCRecordParameters
-------------------

- **mandatory_params**: Sequence of Unsigned integer
- **alpns**: Sequence of String
- **ipv4_hints**: Sequence of String
- **ipv6_hints**: Sequence of String
- **additional_params**: Sequence of :ref:`SVCRecordAdditionalParams <yaml-settings-SVCRecordAdditionalParams>`
- **target**: String
- **port**: Unsigned integer
- **priority**: Unsigned integer
- **no_default_alpn**: Boolean
