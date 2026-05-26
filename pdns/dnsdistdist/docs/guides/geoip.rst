GeoIP (MMDB)
============

:program:`dnsdist`, when compiled with MMDB support, can access MMDB databases to match queries based on origin IP.

Here's a configuration example to make :program:`dnsdist` match queries based on the country of origin.

.. md-tab-set::

   .. md-tab-item:: YAML

      The :ref:`mmdbs <yaml-settings-MmdbConfiguration>` key is used to create a :class:`MMDB` object for MMDB access and :ref:`key_value_stores.mmdb <yaml-settings-KeyValueStoresConfiguration>` is used to create a :class:`KeyValueStore` based on it. The :ref:`query_rules <yaml-settings-QueryRuleConfiguration>` key can then be used to add rules that look up country based on source IP and change response based on country of origin.

      .. code-block:: yaml

        mmdbs:
          - name: test-mmdb
            file_name: /tmp/test-mmdb-db.mmdb
            mmap: true

        key_value_stores:
          mmdb:
            - name: MMDBCountryKV
              mmdb: test-mmdb
              query_params:
                - country
                - iso_code
          lookup_keys:
            source_ip_keys:
              - name: source_ip

        query_rules:
          - name: MMDB Country rule
            selector:
              type: All
            action:
              type: KeyValueStoreLookup
              kvs_name: MMDBCountryKV
              lookup_key_name: source_ip
              destination_tag: kvs-source-ip-result

          - name: Spoof US rule
            selector:
              type: Tag
              tag: kvs-source-ip-result
              value: US
            action:
              type: Spoof
              ips:
                - 5.6.7.8

   .. md-tab-item:: Lua

      The :func:`openMMDB` directive can be used to create a :class:`MMDB` object for MMDB access and :func:`newMMDBKVStore` directive can be used to create a :class:`KeyValueStore` based on it. The :func:`addAction` directive, combined with :func:`KeyValueStoreLookupAction` and :func:`KeyValueLookupKeySourceIP` can then be used to use these in requests.

      .. code-block:: lua

         mmdb = openMMDB('/tmp/test-mmdb-db.mmdb')
         -- creates a KV store based on MMDB, that looks up country.iso_code in MMDB
         kvs = newMMDBKVStore(mmdb, { "country", "iso_code" })
         -- does a lookup in the MMDB database using the source IP as key, and store the result into the 'kvs-source-ip-result' tag
         addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySourceIP(), 'kvs-source-ip-result'))
         -- if the value of the 'kvs-source-ip-result' is set to 'US', spoof a response
         addAction(TagRule('kvs-sourceip-result', 'US'), SpoofAction('5.6.7.8'))
