#!/usr/bin/env python
import os
import unittest

from dnsdisttests import DNSDistTest


@unittest.skipIf('SKIP_DOH_TESTS' in os.environ, 'DNS over HTTPS tests are disabled')
class DNSDistDOHTest(DNSDistTest):

    def getHeaderValue(self, name):
        for header in self._response_headers.decode().splitlines(False):
            values = header.split(':')
            key = values[0]
            if key.lower() == name.lower():
                return values[1].strip()
        return None

    def checkHasHeader(self, name, value):
        got = self.getHeaderValue(name)
        self.assertEqual(got, value)

    def checkNoHeader(self, name):
        self.checkHasHeader(name, None)

    @classmethod
    def setUpClass(cls):

        # for some reason, @unittest.skipIf() is not applied to derived classes with some versions of Python
        if 'SKIP_DOH_TESTS' in os.environ:
            raise unittest.SkipTest('DNS over HTTPS tests are disabled')

        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")
