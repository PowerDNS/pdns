SVCRecordParameters
===================

.. function:: newSVCRecordParameters(priority, target, mandatoryParams, alpns, noDefaultAlpn [, port [, ech [, ipv4hints [, ipv6hints [, additionalParameters ]]]]]) -> SVCRecordParameters

  .. versionadded:: 1.7.0

  Returns a :class:`SVCRecordParameters` to use with :func:`SpoofSVCAction`.

  .. code-block:: Lua

    -- reply to SVCB queries for resolver.powerdns.com. indicating DoT on port 853 of dot.powerdns.com. (192.0.2.1/2001:db8::1), DoH on https://doh.powerdns.com/dns-query (192.0.2.2/2001:db8::2)
    local svc = { newSVCRecordParameters(1, "dot.powerdns.com.", { 3 }, { "dot" }, false, 853, "", { "192.0.2.1" }, { "2001:db8::1" }),
                  newSVCRecordParameters(2, "doh.powerdns.com.", { 3 }, { "h2" },  false, 443, "", { "192.0.2.2" }, { "2001:db8::2" }, { ["42"] = "/dns-query{?dns}" })
                }    
    addAction(AndRule{QTypeRule(64), QNameRule('resolver.powerdns.com.')}, SpoofSVCAction(svc))

  :param int priority: The priority of this record. if more than one record is returned, they all should have different priorities. A priority of 0 indicates Alias mode and no other record should be present in the RRSet.
  :param str target: A domain name indicating the target name.
  :param list of integers mandatoryParams: The numeric values of the supplied parameters that are mandatory for the client to understand.
  :param list of strings alpns: The ALPN values, like "dot" or "h2".
  :param bool noDefaultAlpn: Whether the default ALPN value should be ignored and replaced by the supplied ones.
  :param int port: Optional port to connect to.
  :param str ech: Optional Encrypted Client Hello value, as a raw string (null bytes are supported).
  :param list of strings ipv4hints: Optional list of IPv4 addresses.
  :param list of strings ipv6hints: Optional list of IPv6 addresses.
  :param table of strings additionalParameters: Optional table of additionals parameters. The key should be numerical and will be used as the SvcParamKey, while the value should be a raw binary string (null bytes are supported) and will be passed as the SvcParamValue as-is.

.. class:: SVCRecordParameters

  .. versionadded:: 1.7.0

  Represents Service Binding (SVCB, HTTPS) record parameters, which can be used with :func:`SpoofSVCAction`.
