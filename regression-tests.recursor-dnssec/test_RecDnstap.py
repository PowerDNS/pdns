import os
import socket
import struct
import sys
import threading
import dns
import dnstap_pb2
from nose import SkipTest
from recursortests import RecursorTest

FSTRM_CONTROL_ACCEPT = 0x01
FSTRM_CONTROL_START = 0x02
FSTRM_CONTROL_STOP = 0x03
FSTRM_CONTROL_READY = 0x04
FSTRM_CONTROL_FINISH = 0x05

# Python2/3 compatibility hacks
try:
    from queue import Queue
except ImportError:
    from Queue import Queue

try:
    range = xrange
except NameError:
    pass


def checkDnstapBase(testinstance, dnstap, protocol, initiator):
    testinstance.assertTrue(dnstap)
    testinstance.assertTrue(dnstap.HasField('identity'))
    #testinstance.assertEqual(dnstap.identity, b'a.server')
    testinstance.assertTrue(dnstap.HasField('version'))
    #testinstance.assertIn(b'dnsdist ', dnstap.version)
    testinstance.assertTrue(dnstap.HasField('type'))
    testinstance.assertEqual(dnstap.type, dnstap.MESSAGE)
    testinstance.assertTrue(dnstap.HasField('message'))
    testinstance.assertTrue(dnstap.message.HasField('socket_protocol'))
    testinstance.assertEqual(dnstap.message.socket_protocol, protocol)
    testinstance.assertTrue(dnstap.message.HasField('socket_family'))
    testinstance.assertEquals(dnstap.message.socket_family, dnstap_pb2.INET)
    #
    # We cannot check the query address and port since we only log outgoing queries via dnstap
    #
    #testinstance.assertTrue(dnstap.message.HasField('query_address'))
    #testinstance.assertEquals(socket.inet_ntop(socket.AF_INET, dnstap.message.query_address), initiator)
    testinstance.assertTrue(dnstap.message.HasField('response_address'))
    testinstance.assertEquals(socket.inet_ntop(socket.AF_INET, dnstap.message.response_address), initiator)
    testinstance.assertTrue(dnstap.message.HasField('response_port'))
    testinstance.assertEquals(dnstap.message.response_port, 53)


def checkDnstapQuery(testinstance, dnstap, protocol, initiator='127.0.0.1'):
    testinstance.assertEquals(dnstap.message.type, dnstap_pb2.Message.RESOLVER_QUERY)
    checkDnstapBase(testinstance, dnstap, protocol, initiator)

    testinstance.assertTrue(dnstap.message.HasField('query_time_sec'))
    testinstance.assertTrue(dnstap.message.HasField('query_time_nsec'))

    testinstance.assertTrue(dnstap.message.HasField('query_message'))
    #
    # We cannot compare the incoming query with the outgoing one
    # The IDs and some other fields will be different
    #
    #wire_message = dns.message.from_wire(dnstap.message.query_message)
    #testinstance.assertEqual(wire_message, query)


def checkDnstapExtra(testinstance, dnstap, expected):
    testinstance.assertTrue(dnstap.HasField('extra'))
    testinstance.assertEqual(dnstap.extra, expected)


def checkDnstapNoExtra(testinstance, dnstap):
    testinstance.assertFalse(dnstap.HasField('extra'))


def checkDnstapResponse(testinstance, dnstap, protocol, response, initiator='127.0.0.1'):
    testinstance.assertEquals(dnstap.message.type, dnstap_pb2.Message.RESOLVER_RESPONSE)
    checkDnstapBase(testinstance, dnstap, protocol, initiator)

    testinstance.assertTrue(dnstap.message.HasField('query_time_sec'))
    testinstance.assertTrue(dnstap.message.HasField('query_time_nsec'))

    testinstance.assertTrue(dnstap.message.HasField('response_time_sec'))
    testinstance.assertTrue(dnstap.message.HasField('response_time_nsec'))

    testinstance.assertTrue(dnstap.message.response_time_sec > dnstap.message.query_time_sec or \
                            dnstap.message.response_time_nsec > dnstap.message.query_time_nsec)

    testinstance.assertTrue(dnstap.message.HasField('response_message'))
    wire_message = dns.message.from_wire(dnstap.message.response_message)
    testinstance.assertEqual(wire_message, response)

def fstrm_get_control_frame_type(data):
    (t,) = struct.unpack("!L", data[0:4])
    return t


def fstrm_make_control_frame_reply(cft):
    if cft == FSTRM_CONTROL_READY:
        # Reply with ACCEPT frame and content-type
        contenttype = b'protobuf:dnstap.Dnstap'
        frame = struct.pack('!LLL', FSTRM_CONTROL_ACCEPT, 1,
                            len(contenttype)) + contenttype
        buf = struct.pack("!LL", 0, len(frame)) + frame
        return buf
    elif cft == FSTRM_CONTROL_START:
        return None
    else:
        raise Exception('unhandled control frame ' + cft)


def fstrm_read_and_dispatch_control_frame(conn):
    data = conn.recv(4)
    if not data:
        raise Exception('length of control frame payload could not be read')
    (datalen,) = struct.unpack("!L", data)
    data = conn.recv(datalen)
    cft = fstrm_get_control_frame_type(data)
    reply = fstrm_make_control_frame_reply(cft)
    if reply:
        conn.send(reply)
    return cft


def fstrm_handle_bidir_connection(conn, on_data):
    data = None
    while True:
        data = conn.recv(4)
        if not data:
            break
        (datalen,) = struct.unpack("!L", data)
        if datalen == 0:
            # control frame length follows
            cft = fstrm_read_and_dispatch_control_frame(conn)
            if cft == FSTRM_CONTROL_STOP:
                break
        else:
            # data frame
            data = conn.recv(datalen)
            if not data:
                break

            on_data(data)



class DNSTapServerParams(object):
    def __init__(self, path):
        self.queue = Queue()
        self.path = path


DNSTapServerParameters = DNSTapServerParams("/tmp/dnstap.sock")
DNSTapListeners = []

class TestRecursorDNSTap(RecursorTest):
    @classmethod
    def FrameStreamUnixListener(cls, conn, param):
        while True:
            try:
                fstrm_handle_bidir_connection(conn, lambda data: \
                param.queue.put(data, True, timeout=2.0))
            except socket.error as e:
                if e.errno == 9:
                    break
                sys.stderr.write("Unexpected socket error %s\n" % str(e))
                sys.exit(1)
            except exception as e:
                sys.stderr.write("Unexpected socket error %s\n" % str(e))
                sys.exit(1)                
        conn.close()

    @classmethod
    def FrameStreamUnixListenerMain(cls, param):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                os.remove(param.path)
            except:
                pass
            sock.bind(param.path)
            sock.listen(100)
        except socket.error as e:
            sys.stderr.write("Error binding/listening in the framestream listener: %s\n" % str(e))
            sys.exit(1)
        DNSTapListeners.append(sock)
        while True:
            try:
                (conn, addr) = sock.accept()
                listener = threading.Thread(name='DNSTap Worker', target=cls.FrameStreamUnixListener, args=[conn, param])
                listener.setDaemon(True)
                listener.start()
            except socket.error as e:
                if e.errno != 9:
                    sys.stderr.write("Socket error on accept: %s\n" % str(e))
                else:
                    break
        sock.close()

    @classmethod
    def setUpClass(cls):
        if os.environ.get("NODNSTAPTESTS") == "1":
            raise SkipTest("Not Yet Supported")

        cls.setUpSockets()

        cls.startResponders()

        listener = threading.Thread(name='DNSTap Listener', target=cls.FrameStreamUnixListenerMain, args=[DNSTapServerParameters])
        listener.setDaemon(True)
        listener.start()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    def setUp(self):
        # Make sure the queue is empty, in case
        # a previous test failed
        while not DNSTapServerParameters.queue.empty():
            DNSTapServerParameters.queue.get(False)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
a 3600 IN A 192.0.2.42
tagged 3600 IN A 192.0.2.84
query-selected 3600 IN A 192.0.2.84
answer-selected 3600 IN A 192.0.2.84
types 3600 IN A 192.0.2.84
types 3600 IN AAAA 2001:DB8::1
types 3600 IN TXT "Lorem ipsum dolor sit amet"
types 3600 IN MX 10 a.example.
types 3600 IN SPF "v=spf1 -all"
types 3600 IN SRV 10 20 443 a.example.
cname 3600 IN CNAME a.example.

""".format(soa=cls._SOA))
        super(TestRecursorDNSTap, cls).generateRecursorConfig(confdir)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()
        for listerner in DNSTapListeners:
            listerner.close()

class DNSTapDefaultTest(TestRecursorDNSTap):
    """
    This test makes sure that we correctly export outgoing queries over DNSTap.
    It must be improved and setup env so we can check for incoming responses, but makes sure for now
    that the recursor at least connects to the DNSTap server.
    """

    _confdir = 'DNSTapDefault'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
dnstapFrameStreamServer({"%s"})
    """ % DNSTapServerParameters.path

    def getFirstDnstap(self):
        try:
            data = DNSTapServerParameters.queue.get(True, timeout=2.0)
        except:
            data = False
        self.assertTrue(data)
        dnstap = dnstap_pb2.Dnstap()
        dnstap.ParseFromString(data)
        return dnstap

    def testA(self):
        name = 'www.example.org.'
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)
        self.assertNotEquals(res, None)
        
        # check the dnstap message corresponding to the UDP query
        dnstap = self.getFirstDnstap()

        checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, '127.0.0.8')
        # We don't expect a response
        checkDnstapNoExtra(self, dnstap)

class DNSTapLogNoQueriesTest(TestRecursorDNSTap):
    """
    This test makes sure that we correctly export outgoing queries over DNSTap.
    It must be improved and setup env so we can check for incoming responses, but makes sure for now
    that the recursor at least connects to the DNSTap server.
    """

    _confdir = 'DNSTapLogNoQueries'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
dnstapFrameStreamServer({"%s"}, {logQueries=false})
    """ % (DNSTapServerParameters.path)

    def testA(self):
        name = 'www.example.org.'
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)
        self.assertNotEquals(res, None)

        # We don't expect anything
        self.assertTrue(DNSTapServerParameters.queue.empty())
