#!/usr/bin/env python
import os
import unittest
from dnsdistDynBlockTests import DynBlocksTest

@unittest.skipUnless('ENABLE_SUDO_TESTS' in os.environ, "sudo is not available")
class TestDynBlockEBPFQPS(DynBlocksTest):

    _config_template = """
    bpf = newBPFFilter({ipv4MaxItems=10, ipv6MaxItems=10, qnamesMaxItems=10})
    setDefaultBPFFilter(bpf)
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d)
    function maintenance()
        dbr:apply()
    end

    -- not going to wait 60s!
    setDynBlocksPurgeInterval(1)

    -- exercise the manual blocking methods
    bpf:block(newCA("2001:DB8::42"))
    bpf:blockQName(newDNSName("powerdns.com."), 255)
    bpf:getStats()
    bpf:unblock(newCA("2001:DB8::42"))
    bpf:unblockQName(newDNSName("powerdns.com."), 255)

    newServer{address="127.0.0.1:%d"}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _sudoMode = True

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate
        """
        name = 'qrate.dynblocks.tests.powerdns.com.'
        self.doTestQRate(name, ebpf=True)
