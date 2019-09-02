Checking available features
===========================
.. versionadded:: 4.3.0
                  
To check if a Lua features is available, consult the global
``pdns_features`` table. This table contains string keys with a values
of type boolean, string or number. If a key is absent the value will
evaluate to ``nil``, indicating the feature is not available.

Currently, the following keys are defined:

.. code-block:: Lua
                
    pdns_feature["PR8001_devicename"] = true


