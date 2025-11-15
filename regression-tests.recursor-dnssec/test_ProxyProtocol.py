import dns
import os
import socket
import struct
import time
import requests
import subprocess

try:
    range = xrange
except NameError:
    pass

from recursortests import RecursorTest
from proxyprotocol import ProxyProtocol

class ProxyProtocolAllowedTest(RecursorTest):
    _confdir = 'ProxyProtocolAllowed'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _lua_dns_script_file = """

    function gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp, proxyProtocolValues)
      local remoteaddr = remote:toStringWithPort()
      local localaddr = localip:toStringWithPort()
      local foundFoo = false
      local foundBar = false

      if remoteaddr ~= '127.0.0.42:0' and remoteaddr ~= '[::42]:0' then
        pdnslog('gettag: invalid source '..remoteaddr)
        return 1
      end
      if localaddr ~= '255.255.255.255:65535' and localaddr ~= '[2001:db8::ff]:65535' then
        pdnslog('gettag: invalid dest '..localaddr)
        return 2
      end

      for k,v in pairs(proxyProtocolValues) do
        local type = v:getType()
        local content = v:getContent()
        if type == 0 and content == 'foo' then
          foundFoo = true
        end
        if type == 255 and content == 'bar' then
          foundBar = true
        end
      end

      if not foundFoo or not foundBar then
        pdnslog('gettag: TLV not found')
        return 3
      end

      return 42
    end

    function preresolve(dq)
      local foundFoo = false
      local foundBar = false
      local values = dq:getProxyProtocolValues()
      for k,v in pairs(values) do
        local type = v:getType()
        local content = v:getContent()
        if type == 0 and content == 'foo' then
          foundFoo = true
        end
        if type == 255 and content == 'bar' then
          foundBar = true
        end
      end

      if not foundFoo or not foundBar then
        pdnslog('TLV not found')
        dq:addAnswer(pdns.A, '192.0.2.255', 60)
        return true
      end

      local remoteaddr = dq.remoteaddr:toStringWithPort()
      local localaddr = dq.localaddr:toStringWithPort()

      if remoteaddr ~= '127.0.0.42:0' and remoteaddr ~= '[::42]:0' then
        pdnslog('invalid source '..remoteaddr)
        dq:addAnswer(pdns.A, '192.0.2.128', 60)
        return true
      end
      if localaddr ~= '255.255.255.255:65535' and localaddr ~= '[2001:db8::ff]:65535' then
        pdnslog('invalid dest '..localaddr)
        dq:addAnswer(pdns.A, '192.0.2.129', 60)
        return true
      end

      if dq.tag ~= 42 then
        pdnslog('invalid tag '..dq.tag)
        dq:addAnswer(pdns.A, '192.0.2.130', 60)
        return true
      end

      local interfaceremoteaddr = dq.interface_remoteaddr:toString()
      local interfacelocaladdr = dq.interface_localaddr:toStringWithPort()

      if interfaceremoteaddr ~= '127.0.0.1' and interfaceremoteaddr ~= '[::]' then
        pdnslog('invalid interface source '..interfaceremoteaddr)
        dq:addAnswer(pdns.A, '192.0.2.131', 60)
        return true
      end
      if interfacelocaladdr ~= '127.0.0.1:%d' and interfacelocaladdr ~= '[::1]:%d' then
        pdnslog('invalid interfacedest '..interfacelocaladdr)
        dq:addAnswer(pdns.A, '192.0.2.132', 60)
        return true
      end

      dq:addAnswer(pdns.A, '192.0.2.1', 60)
      return true
    end
    """ % (RecursorTest._recursorPort, RecursorTest._recursorPort)

    _config_template = """
    proxy-protocol-from=127.0.0.1
    proxy-protocol-maximum-size=512
    allow-from=127.0.0.0/24, ::1/128, ::42/128
    webserver=yes
    webserver-port=%d
    webserver-address=127.0.0.1
    webserver-password=%s
api-key=%s

""" % (_wsPort, _wsPassword, _apiKey)

    def checkStats(self, expected127001):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/jsonstat?command=get-remote-ring&name=remotes'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        # We allow all kind of entries, but 127.0.0.1 must have the given value, due to the
        # testLocalProxyProtocol test, which actually does not set a source address.  If we see a
        # higher value than expected, some ProxyProtocol clients were accounted as 127.0.0.1, which
        # is not right as all other tests set a source addres other than 127.0.0.1
        for entry in content['entries']:
            if entry[1] == '127.0.0.1':
                self.assertEqual(entry[0], expected127001)

    def testLocalProxyProtocol(self):
        qname = 'local.proxy-protocol.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.255')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        queryPayload = query.to_wire()
        ppPayload = ProxyProtocol.getPayload(True, False, False, None, None, None, None, [])
        payload = ppPayload + queryPayload

        # UDP
        self._sock.settimeout(2.0)

        try:
            self._sock.send(payload)
            data = self._sock.recv(4096)
        except socket.timeout:
            data = None
        finally:
            self._sock.settimeout(None)

        res = None
        if data:
            res = dns.message.from_wire(data)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkStats(1)

        # TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", self._recursorPort))

        try:
            sock.send(ppPayload)
            sock.send(struct.pack("!H", len(queryPayload)))
            sock.send(queryPayload)
            data = sock.recv(2)
            if data:
                (datalen,) = struct.unpack("!H", data)
                data = sock.recv(datalen)
        except socket.timeout as e:
            print("Timeout: %s" % (str(e)))
            data = None
        except socket.error as e:
            print("Network error: %s" % (str(e)))
            data = None
        finally:
            sock.close()

        res = None
        if data:
            res = dns.message.from_wire(data)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkStats(2)

    def testInvalidMagicProxyProtocol(self):
        qname = 'invalid-magic.proxy-protocol.recursor-tests.powerdns.com.'

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        queryPayload = query.to_wire()
        ppPayload = ProxyProtocol.getPayload(True, False, False, None, None, None, None, [])
        ppPayload = b'\x00' + ppPayload[1:]
        payload = ppPayload + queryPayload

        # UDP
        self._sock.settimeout(2.0)

        try:
            self._sock.send(payload)
            data = self._sock.recv(4096)
        except socket.timeout:
            data = None
        finally:
            self._sock.settimeout(None)

        res = None
        if data:
            res = dns.message.from_wire(data)
        self.assertEqual(res, None)

        # TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", self._recursorPort))

        try:
            sock.send(ppPayload)
            sock.send(struct.pack("!H", len(queryPayload)))
            sock.send(queryPayload)
            data = sock.recv(2)
            if data:
                (datalen,) = struct.unpack("!H", data)
                data = sock.recv(datalen)
        except socket.timeout as e:
            print("Timeout: %s" % (str(e)))
            data = None
        except socket.error as e:
            print("Network error: %s" % (str(e)))
            data = None
        finally:
            sock.close()

        res = None
        if data:
            res = dns.message.from_wire(data)
        self.assertEqual(res, None)

    def testTCPOneByteAtATimeProxyProtocol(self):
        qname = 'tcp-one-byte-at-a-time.proxy-protocol.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        queryPayload = query.to_wire()
        ppPayload = ProxyProtocol.getPayload(False, True, False, '127.0.0.42', '255.255.255.255', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])

        # TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", self._recursorPort))

        try:
            for i in range(len(ppPayload)):
                sock.send(ppPayload[i:i+1])
                time.sleep(0.01)
            value = struct.pack("!H", len(queryPayload))
            for i in range(len(value)):
                sock.send(value[i:i+1])
                time.sleep(0.01)
            for i in range(len(queryPayload)):
                sock.send(queryPayload[i:i+1])
                time.sleep(0.01)

            data = sock.recv(2)
            if data:
                (datalen,) = struct.unpack("!H", data)
                data = sock.recv(datalen)
        except socket.timeout as e:
            print("Timeout: %s" % (str(e)))
            data = None
        except socket.error as e:
            print("Network error: %s" % (str(e)))
            data = None
        finally:
            sock.close()

        res = None
        if data:
            res = dns.message.from_wire(data)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)

    def testTooLargeProxyProtocol(self):
        # the total payload (proxy protocol + DNS) is larger than proxy-protocol-maximum-size
        # so it should be dropped
        qname = 'too-large.proxy-protocol.recursor-tests.powerdns.com.'

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        queryPayload = query.to_wire()
        ppPayload = ProxyProtocol.getPayload(False, True, False, '127.0.0.42', '255.255.255.255', 0, 65535, [ [0, b'foo' ], [1, b'A'*512], [ 255, b'bar'] ])
        payload = ppPayload + queryPayload

        # UDP
        self._sock.settimeout(2.0)

        try:
            self._sock.send(payload)
            data = self._sock.recv(4096)
        except socket.timeout:
            data = None
        finally:
            self._sock.settimeout(None)

        res = None
        if data:
            res = dns.message.from_wire(data)
        self.assertEqual(res, None)

        # TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", self._recursorPort))

        try:
            sock.send(ppPayload)
            sock.send(struct.pack("!H", len(queryPayload)))
            sock.send(queryPayload)

            data = sock.recv(2)
            if data:
                (datalen,) = struct.unpack("!H", data)
                data = sock.recv(datalen)
        except socket.timeout as e:
            print("Timeout: %s" % (str(e)))
            data = None
        except socket.error as e:
            print("Network error: %s" % (str(e)))
            data = None
        finally:
            sock.close()

        res = None
        if data:
            res = dns.message.from_wire(data)
        self.assertEqual(res, None)

    def testNoHeaderProxyProtocol(self):
        qname = 'no-header.proxy-protocol.recursor-tests.powerdns.com.'

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertEqual(res, None)

    def testIPv4ProxyProtocol(self):
        qname = 'ipv4.proxy-protocol.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, False, '127.0.0.42', '255.255.255.255', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testIPv4NoValuesProxyProtocol(self):
        qname = 'ipv4-no-values.proxy-protocol.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.255')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, False, '127.0.0.42', '255.255.255.255', 0, 65535)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testIPv4ProxyProtocolNotAuthorized(self):
        qname = 'ipv4-not-authorized.proxy-protocol.recursor-tests.powerdns.com.'

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, False, '192.0.2.255', '255.255.255.255', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])
            self.assertEqual(res, None)

    def testIPv6ProxyProtocol(self):
        qname = 'ipv6.proxy-protocol.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, True, '::42', '2001:db8::ff', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testIPv6NoValuesProxyProtocol(self):
        qname = 'ipv6-no-values.proxy-protocol.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.255')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, True, '::42', '2001:db8::ff', 0, 65535)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testIPv6ProxyProtocolNotAuthorized(self):
        qname = 'ipv6-not-authorized.proxy-protocol.recursor-tests.powerdns.com.'

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, True, '2001:db8::1', '2001:db8::ff', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])
            self.assertEqual(res, None)

    def testIPv6ProxyProtocolSeveralQueriesOverTCP(self):
        qname = 'several-queries-tcp.proxy-protocol.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        queryPayload = query.to_wire()
        ppPayload = ProxyProtocol.getPayload(False, True, True, '::42', '2001:db8::ff', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])

        # TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", self._recursorPort))

        sock.send(ppPayload)

        count = 0
        for idx in range(5):
            try:
                sock.send(struct.pack("!H", len(queryPayload)))
                sock.send(queryPayload)

                data = sock.recv(2)
                if data:
                    (datalen,) = struct.unpack("!H", data)
                    data = sock.recv(datalen)
            except socket.timeout as e:
                print("Timeout: %s" % (str(e)))
                break
            except socket.error as e:
                print("Network error: %s" % (str(e)))
                break

            res = None
            if data:
                res = dns.message.from_wire(data)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)
            count = count + 1

        self.assertEqual(count, 5)
        sock.close()

class ProxyProtocolAllowedFFITest(ProxyProtocolAllowedTest):
    # same tests than ProxyProtocolAllowedTest but with the Lua FFI interface instead of the regular one
    _confdir = 'ProxyProtocolAllowedFFI'
    _lua_dns_script_file = """
    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      typedef struct pdns_proxyprotocol_value {
        uint8_t     type;
        uint16_t    len;
        const void* data;
      } pdns_proxyprotocol_value_t;

      size_t pdns_ffi_param_get_proxy_protocol_values(pdns_ffi_param_t* ref, const pdns_proxyprotocol_value_t** out);
      const char* pdns_ffi_param_get_remote(pdns_ffi_param_t* ref);
      const char* pdns_ffi_param_get_local(pdns_ffi_param_t* ref);
      uint16_t pdns_ffi_param_get_remote_port(const pdns_ffi_param_t* ref);
      uint16_t pdns_ffi_param_get_local_port(const pdns_ffi_param_t* ref);

      const char* pdns_ffi_param_get_interface_remote(pdns_ffi_param_t* ref);
      const char* pdns_ffi_param_get_interface_local(pdns_ffi_param_t* ref);
      uint16_t pdns_ffi_param_get_interface_remote_port(const pdns_ffi_param_t* ref);
      uint16_t pdns_ffi_param_get_interface_local_port(const pdns_ffi_param_t* ref);

      void pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag);
    ]]

    function gettag_ffi(obj)
      local remoteaddr = ffi.string(ffi.C.pdns_ffi_param_get_remote(obj))
      local localaddr = ffi.string(ffi.C.pdns_ffi_param_get_local(obj))
      local foundFoo = false
      local foundBar = false

      if remoteaddr ~= '127.0.0.42' and remoteaddr ~= '::42' then
        pdnslog('gettag-ffi: invalid source '..remoteaddr)
        ffi.C.pdns_ffi_param_set_tag(obj, 1)
        return
      end
      if localaddr ~= '255.255.255.255' and localaddr ~= '2001:db8::ff' then
        pdnslog('gettag-ffi: invalid dest '..localaddr)
        ffi.C.pdns_ffi_param_set_tag(obj, 2)
        return
      end

      if ffi.C.pdns_ffi_param_get_remote_port(obj) ~= 0 then
        pdnslog('gettag-ffi: invalid source port '..ffi.C.pdns_ffi_param_get_remote_port(obj))
        ffi.C.pdns_ffi_param_set_tag(obj, 1)
        return
      end

      if ffi.C.pdns_ffi_param_get_local_port(obj) ~= 65535 then
        pdnslog('gettag-ffi: invalid source port '..ffi.C.pdns_ffi_param_get_local_port(obj))
        ffi.C.pdns_ffi_param_set_tag(obj, 2)
        return
      end

      local interfaceremoteaddr = ffi.string(ffi.C.pdns_ffi_param_get_interface_remote(obj))
      local interfacelocaladdr = ffi.string(ffi.C.pdns_ffi_param_get_interface_local(obj))

      if interfaceremoteaddr ~= '127.0.0.1' and remoteaddr ~= '::1' then
        pdnslog('gettag-ffi: invalid interface source '..interfaceremoteaddr)
        ffi.C.pdns_ffi_param_set_tag(obj, 1)
        return
      end
      if interfacelocaladdr ~= '127.0.0.1' and interfacelocaladdr ~= '::1' then
        pdnslog('gettag-ffi: invalid interface dest '..interfacelocaladdr)
        ffi.C.pdns_ffi_param_set_tag(obj, 2)
        return
      end

      if ffi.C.pdns_ffi_param_get_interface_local_port(obj) ~= %d then
        pdnslog('gettag-ffi: invalid interface source port '..ffi.C.pdns_ffi_param_get_interface_local_port(obj))
        ffi.C.pdns_ffi_param_set_tag(obj, 2)
        return
      end

      local ret_ptr = ffi.new("const pdns_proxyprotocol_value_t *[1]")
      local ret_ptr_param = ffi.cast("const pdns_proxyprotocol_value_t **", ret_ptr)
      local values_count = ffi.C.pdns_ffi_param_get_proxy_protocol_values(obj, ret_ptr_param)

      if values_count > 0 then
        for i = 0,tonumber(values_count)-1 do
          local type = ret_ptr[0][i].type
          local content = ffi.string(ret_ptr[0][i].data, ret_ptr[0][i].len)
          if type == 0 and content == 'foo' then
            foundFoo = true
          end
          if type == 255 and content == 'bar' then
            foundBar = true
          end
        end
      end

      if not foundFoo or not foundBar then
        pdnslog('gettag-ffi: TLV not found')
        ffi.C.pdns_ffi_param_set_tag(obj, 3)
        return
      end

      ffi.C.pdns_ffi_param_set_tag(obj, 42)
    end

    function preresolve(dq)
      local foundFoo = false
      local foundBar = false
      local values = dq:getProxyProtocolValues()
      for k,v in pairs(values) do
        local type = v:getType()
        local content = v:getContent()
        if type == 0 and content == 'foo' then
          foundFoo = true
        end
        if type == 255 and content == 'bar' then
          foundBar = true
        end
      end

      if not foundFoo or not foundBar then
        pdnslog('TLV not found')
        dq:addAnswer(pdns.A, '192.0.2.255', 60)
        return true
      end

      local remoteaddr = dq.remoteaddr:toStringWithPort()
      local localaddr = dq.localaddr:toStringWithPort()

      if remoteaddr ~= '127.0.0.42:0' and remoteaddr ~= '[::42]:0' then
        pdnslog('invalid source '..remoteaddr)
        dq:addAnswer(pdns.A, '192.0.2.128', 60)
        return true
      end
      if localaddr ~= '255.255.255.255:65535' and localaddr ~= '[2001:db8::ff]:65535' then
        pdnslog('invalid dest '..localaddr)
        dq:addAnswer(pdns.A, '192.0.2.129', 60)
        return true
      end

      if dq.tag ~= 42 then
        pdnslog('invalid tag '..dq.tag)
        dq:addAnswer(pdns.A, '192.0.2.130', 60)
        return true
      end

      dq:addAnswer(pdns.A, '192.0.2.1', 60)
      return true
    end
    """ % (ProxyProtocolAllowedTest._recursorPort)

class ProxyProtocolNotAllowedTest(RecursorTest):
    _confdir = 'ProxyProtocolNotAllowed'
    _lua_dns_script_file = """

    function preresolve(dq)
      dq:addAnswer(pdns.A, '192.0.2.1', 60)
      return true
    end
    """

    _config_template = """
    proxy-protocol-from=192.0.2.1/32
    allow-from=127.0.0.0/24, ::1/128
""" % ()

    def testNoHeaderProxyProtocol(self):
        qname = 'no-header.proxy-protocol-not-allowed.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testIPv4ProxyProtocol(self):
        qname = 'ipv4.proxy-protocol-not-allowed.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, False, '127.0.0.42', '255.255.255.255', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])
            self.assertEqual(res, None)

class ProxyProtocolExceptionTest(RecursorTest):
    _confdir = 'ProxyProtocolException'
    _lua_dns_script_file = """

    function preresolve(dq)
      dq:addAnswer(pdns.A, '192.0.2.1', 60)
      return true
    end
    """

    _config_template = """
    proxy-protocol-from=127.0.0.1/32
    proxy-protocol-exceptions=127.0.0.1:%d
    allow-from=127.0.0.0/24, ::1/128
""" % (RecursorTest._recursorPort)

    def testNoHeaderProxyProtocol(self):
        qname = 'no-header.proxy-protocol-not-allowed.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testIPv4ProxyProtocol(self):
        qname = 'ipv4.proxy-protocol-not-allowed.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, False, '127.0.0.42', '255.255.255.255', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])
            self.assertEqual(res, None)

class ProxyProtocolConfigReloadTest(RecursorTest):
    _confdir = 'ProxyProtocolConfigReload'
    _lua_dns_script_file = """

    function preresolve(dq)
      dq:addAnswer(pdns.A, '192.0.2.1', 60)
      return true
    end
    """

    _config_template = """
    proxy-protocol-from=128.0.0.1/32
    allow-from=127.0.0.0/24, ::1/128
"""

    def testIPv4ProxyProtocol(self):
        qname = 'ipv4.proxy-protocol-not-allowed.recursor-tests.powerdns.com.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.1')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, False, '127.0.0.42', '255.255.255.255', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])
            self.assertEqual(res, None)
        ProxyProtocolConfigReloadTest._config_template = """
        proxy-protocol-from=127.0.0.1/32
        allow-from=127.0.0.0/24, ::1/128
"""
        confdir = os.path.join('configs', ProxyProtocolConfigReloadTest._confdir)
        ProxyProtocolConfigReloadTest.generateRecursorConfig(confdir)
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % confdir,
                          'reload-acls']
        try:
            subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError('%s failed (%d): %s' % (rec_controlCmd, e.returncode, e.output))

        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, False, '127.0.0.42', '255.255.255.255', 0, 65535, [ [0, b'foo' ], [ 255, b'bar'] ])
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)
