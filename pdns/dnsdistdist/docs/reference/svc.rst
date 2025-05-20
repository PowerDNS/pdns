SVCRecordParameters
===================

.. function:: newSVCRecordParameters(priority, target[, SVCParams]) -> SVCRecordParameters

  .. versionadded:: 1.7.0

  Returns a :class:`SVCRecordParameters` to use with :func:`SpoofSVCAction`.

  .. code-block:: Lua

    -- reply to SVCB queries for _dns.resolver.arpa. indicating DoT on port 853 of dot.powerdns.com. (192.0.2.1/2001:db8::1), DoH on https://doh.powerdns.com/dns-query (192.0.2.2/2001:db8::2)
    local svc = { newSVCRecordParameters(1, "dot.powerdns.com.", { mandatory={"port"}, alpn={ "dot" }, noDefaultAlpn=true, port=853, ipv4hint={ "192.0.2.1" }, ipv6hint={ "2001:db8::1" } }),
                  newSVCRecordParameters(2, "doh.powerdns.com.", { mandatory={"port"}, alpn={ "h2" }, port=443, ipv4hint={ "192.0.2.2" }, ipv6hint={ "2001:db8::2" }, key7 = "/dns-query{?dns}" })
                }
    addAction(AndRule{QTypeRule(64), QNameRule('_dns.resolver.arpa.')}, SpoofSVCAction(svc))
    -- reply with NODATA (NXDOMAIN would deny all types at that name and below, including SVC) for other types
    addAction(QNameRule('_dns.resolver.arpa.'), NegativeAndSOAAction(false, '_dns.resolver.arpa.', 3600, 'fake.resolver.arpa.', 'fake.resolver.arpa.', 1, 1800, 900, 604800, 86400))


  :param int priority: The priority of this record. if more than one record is returned, they all should have different priorities. A priority of 0 indicates Alias mode and no other record should be present in the RRSet.
  :param str target: A domain name indicating the target name.
  :param table SVCParams: Optional table of additional parameters. The key should be the name of the SVC parameter and will be used as the SvcParamKey, while the value depends on the key (see below)

  These SVCParams can be set::

    {
      mandatory={STRING},   -- The mandatory keys. the table of strings must be the key names (like "port" and "key998").
      alpn={STRING},        -- alpns for this record, like "dot" or "h2".
      noDefaultAlpn=BOOL,   -- When true, the no-default-alpn key is included in the record, false or absent means it does not exist in the record.
      port=NUM,             -- Port parameter to include.
      ipv4hint={STRING},    -- IPv4 hints to include into the record.
      ech=STRING,           -- Encrypted Client Hello as a raw string (can include null bytes).
      ipv6hint={STRING}     -- IPv6 hints to include into the record.
    }

  Any other parameters can be set by using the ``keyNNNN`` syntax and must use a raw string. Like this::

    key776="hello\0world"

.. class:: SVCRecordParameters

  .. versionadded:: 1.7.0

  Represents Service Binding (SVCB, HTTPS) record parameters, which can be used with :func:`SpoofSVCAction`.
