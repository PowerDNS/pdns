#!/usr/bin/env python
import base64
import socket
import time
import dns
from dnsdisttests import DNSDistTest
from dnsdistDynBlockTests import DynBlocksTest, waitForMaintenanceToRun, _maintenanceWaitTime

class TestDynBlockGroupServFailsRatio(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio
        """
        name = 'servfailratio.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRatio(name, dns.rcode.SERVFAIL, 10, 10)

class TestDynBlockGroupCacheMissRatio(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setCacheMissRatio(0.8, %d, "Exceeded cache miss ratio", %d, 20, 0.0)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    local pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """

    def testDynBlocksCacheMissRatio(self):
        """
        Dyn Blocks (group): Cache miss ratio
        """
        name = 'cachemissratio.group.dynblocks.tests.powerdns.com.'
        self.doTestCacheMissRatio(name, 3, 17)
