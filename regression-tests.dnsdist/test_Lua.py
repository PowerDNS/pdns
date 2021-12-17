#!/usr/bin/env python

import base64
import time
import unittest
from dnsdisttests import DNSDistTest

class TestLuaThread(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _config_params = ['_consoleKeyB64', '_consolePort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")

    counter = 0
    function threadmessage(cmd, data)
        print("counter says", cmd, data.i)
        counter = tonumber(data.i)
    end

    newThread([==[
      local socket = require'socket'
      local i=1
      while true
      do
          socket.sleep(1)
          submitToMainThread("setCounter", {i=i})
          i = i + 1
      end
    ]==])
    """

    def testLuaThreadCounter(self):
        """
        LuaThread: Test the lua newThread interface
        """
        count1 = self.sendConsoleCommand('counter')
        time.sleep(3)
        count2 = self.sendConsoleCommand('counter')
        self.assertTrue(count2 > count1)
