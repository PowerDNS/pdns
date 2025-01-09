.. raw:: latex

    \setcounter{secnumdepth}{-1}

YAML support structures
=======================

.. _yaml-settings-ResponseConfig:

ResponseConfig
--------------

- **set-aa**: Boolean
- **set-ad**: Boolean
- **set-ra**: Boolean
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

- **mandatory-params**: Sequence of Unsigned integer
- **alpns**: Sequence of String
- **ipv4-hints**: Sequence of String
- **ipv6-hints**: Sequence of String
- **additional_params**: Sequence of :ref:`SVCRecordAdditionalParams <yaml-settings-SVCRecordAdditionalParams>`
- **target**: String
- **port**: Unsigned integer
- **priority**: Unsigned integer
- **no-default-alpn**: Boolean
