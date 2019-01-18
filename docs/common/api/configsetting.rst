ConfigSetting
=============

.. json:object:: ConfigSetting

  Represents a configuration item (as found in :doc:'../settings')

  :property string type: set to "ConfigSetting"
  :property string name: The name of this setting (e.g. 'webserver-port')
  :property string value: The value of setting ``name``

  **Example:**

  .. code-block:: json

    {
      "name": "webserver-port",
      "type": "ConfigSetting",
      "value": "8081"
    }
