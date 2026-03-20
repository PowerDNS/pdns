Checking available features
===========================

.. versionadded:: 2.2.0

To check if a Lua feature is available, consult the global ``pdns_features`` table. This table contains string keys with values of type boolean, string or number. If a key is absent the value will evaluate to ``nil``, indicating the feature is not available.

Currently, the following keys are defined:

.. code-block:: Lua

    pdns_features["PR17017_protobuf_tags_prefixes"] = true
