import dns
import os
import extendederrors

from recursortests import RecursorTest

class ExtendedErrorsRecursorTest(RecursorTest):

    _confdir = 'ExtendedErrors'
    _config_template_default = """
dnssec=validate
daemon=no
trace=yes
packetcache-ttl=0
packetcache-servfail-ttl=0
max-cache-ttl=15
threads=1
loglevel=9
disable-syslog=yes
log-common-errors=yes
"""
    _config_template = """
    extended-errors=yes
    """
    _lua_dns_script_file = """
    function preresolve(dq)
      if dq.qname == newDN('fromlua.extended.') then
        dq.extendedErrorCode = 10
        dq.extendedErrorExtra = "Extra text from Lua!"
        return true
      end
      if dq.qname == newDN('toolarge.extended.') then
        dq:addRecord(pdns.TXT, '%s', pdns.place.ANSWER)
        dq.extendedErrorCode = 10
        dq.extendedErrorExtra = "Extra text from Lua!"
        return true
      end
      return false
    end

    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref) __attribute__ ((visibility ("default")));
      void pdns_ffi_param_set_rcode(pdns_ffi_param_t* ref, int rcode) __attribute__ ((visibility ("default")));
      void pdns_ffi_param_set_extended_error_code(pdns_ffi_param_t* ref, uint16_t code) __attribute__ ((visibility ("default")));
      void pdns_ffi_param_set_extended_error_extra(pdns_ffi_param_t* ref, size_t len, const char* extra);
    ]]

    function gettag_ffi(obj)
      local qname = ffi.string(ffi.C.pdns_ffi_param_get_qname(obj))
      if qname == 'fromluaffi.extended' then
        ffi.C.pdns_ffi_param_set_rcode(obj, 0)
        ffi.C.pdns_ffi_param_set_extended_error_code(obj, 10)
        local extra = 'Extra text from Lua FFI!'
        ffi.C.pdns_ffi_param_set_extended_error_extra(obj, #extra, extra)
      end
      return {}
    end
    """ % ('A'*427)

    _roothints = None

    @classmethod
    def setUpClass(cls):

        # we don't need all the auth stuff
        cls.setUpSockets()
        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ExtendedErrorsRecursorTest, cls).generateRecursorConfig(confdir)

    def testNotIncepted(self):
        qname = 'signotincepted.bad-dnssec.wb.sidnlabs.nl.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, timeout=5.0)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
            self.assertEqual(res.edns, 0)
            self.assertEqual(len(res.options), 1)
            self.assertEqual(res.options[0].otype, 15)
            self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(8, b''))

    def testExpired(self):
        qname = 'sigexpired.bad-dnssec.wb.sidnlabs.nl.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, timeout=5.0)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
            self.assertEqual(res.edns, 0)
            self.assertEqual(len(res.options), 1)
            self.assertEqual(res.options[0].otype, 15)
            self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(7, b''))

    def testBogus(self):
        qname = 'unknownalgorithm.bad-dnssec.wb.sidnlabs.nl.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, timeout=5.0)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
            self.assertEqual(res.edns, 0)
            self.assertEqual(len(res.options), 1)
            self.assertEqual(res.options[0].otype, 15)
            self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(6, b''))

    def testMissingRRSIG(self):
        qname = 'brokendnssec.net.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, timeout=5.0)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
            self.assertEqual(res.edns, 0)
            self.assertEqual(len(res.options), 1)
            self.assertEqual(res.options[0].otype, 15)
            self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(10, b''))

    def testFromLua(self):
        qname = 'fromlua.extended.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, timeout=5.0)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(res.edns, 0)
            self.assertEqual(len(res.options), 1)
            self.assertEqual(res.options[0].otype, 15)
            self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(10, b'Extra text from Lua!'))

    def testFromLuaFFI(self):
        qname = 'fromluaffi.extended.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, timeout=5.0)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(res.edns, 0)
            self.assertEqual(len(res.options), 1)
            self.assertEqual(res.options[0].otype, 15)
            self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(10, b'Extra text from Lua FFI!'))

    def testTooLarge(self):
        qname = 'toolarge.extended.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True, payload=512)

        # should not have the Extended Option since the packet is too large already
        res = self.sendUDPQuery(query, timeout=5.0)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEquals(len(res.answer), 1)
        self.assertEqual(res.edns, 0)
        self.assertEqual(len(res.options), 0)

        res = self.sendTCPQuery(query, timeout=5.0)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEquals(len(res.answer), 1)
        self.assertEqual(res.edns, 0)
        self.assertEqual(len(res.options), 1)
        self.assertEqual(res.options[0].otype, 15)
        self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(10, b'Extra text from Lua!'))

class NoExtendedErrorsRecursorTest(RecursorTest):

    _confdir = 'ExtendedErrorsDisabled'
    _config_template_default = """
dnssec=validate
daemon=no
trace=yes
packetcache-ttl=0
packetcache-servfail-ttl=0
max-cache-ttl=15
threads=1
loglevel=9
disable-syslog=yes
log-common-errors=yes
"""
    _config_template = """
    extended-errors=no
    """
    _roothints = None

    @classmethod
    def setUpClass(cls):

        # we don't need all the auth stuff
        cls.setUpSockets()
        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(NoExtendedErrorsRecursorTest, cls).generateRecursorConfig(confdir)

    def testNotIncepted(self):
        qname = 'signotincepted.bad-dnssec.wb.sidnlabs.nl.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, timeout=5.0)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
            self.assertEqual(res.edns, 0)
            self.assertEqual(len(res.options), 0)
