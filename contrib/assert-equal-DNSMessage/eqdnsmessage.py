import difflib
import dns
import unittest

class AssertEqualDNSMessageMixin(unittest.TestCase):
    def assertEqualDNSMessage(self, first, second, msg=None):
        if not first == second:
            a = str(first).split('\n')
            b = str(second).split('\n')

            diff = '\n'.join(
                difflib.unified_diff(
                    a,
                    b,
                    fromfile='first',
                    tofile='second',
                    n=max(len(a), len(b)),
                    lineterm=""
                )
            )

            standardMsg = "%s != %s:\n%s" % (repr(first), repr(second), diff)
            msg = self._formatMessage(msg, standardMsg)

            raise self.failureException(msg)

    def setUp(self):
        self.addTypeEqualityFunc(dns.message.Message, self.assertEqualDNSMessage)

        super(AssertEqualDNSMessageMixin, self).setUp()