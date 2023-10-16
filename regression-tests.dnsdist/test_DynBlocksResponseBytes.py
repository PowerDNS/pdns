#!/usr/bin/env python
import base64
import socket
import time
import dns
from dnsdisttests import DNSDistTest
from dnsdistDynBlockTests import DynBlocksTest, waitForMaintenanceToRun, _maintenanceWaitTime

class TestDynBlockResponseBytes(DynBlocksTest):

    _dynBlockBytesPerSecond = 200
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_dynBlockBytesPerSecond', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    function maintenance()
	    addDynBlocks(exceedRespByterate(%d, %d), "Exceeded response byterate", %d)
    end
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksResponseByteRate(self):
        """
        Dyn Blocks: Response Byte Rate
        """
        name = 'responsebyterate.dynblocks.tests.powerdns.com.'
        self.doTestResponseByteRate(name, self._dynBlockBytesPerSecond)

class TestDynBlockGroupResponseBytes(DynBlocksTest):

    _dynBlockBytesPerSecond = 200
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_dynBlockBytesPerSecond', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    local dbr = dynBlockRulesGroup()
    dbr:setResponseByteRate(%d, %d, "Exceeded query rate", %d)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksResponseByteRate(self):
        """
        Dyn Blocks (group) : Response Byte Rate
        """
        name = 'responsebyterate.group.dynblocks.tests.powerdns.com.'
        self.doTestResponseByteRate(name, self._dynBlockBytesPerSecond)
