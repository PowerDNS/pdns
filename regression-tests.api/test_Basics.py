import requests
import socket
import time
from test_helper import ApiTestCase


class TestBasics(ApiTestCase):

    def test_unauth(self):
        r = requests.get(self.url("/servers/localhost"))
        self.assertEquals(r.status_code, requests.codes.unauthorized)

    def test_split_request(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((self.server_address, self.server_port))

        parts = ("GET / HTTP/1.0\r\n", "Content-Type: text/plain\r\n\r\n")

        print("Sending request")
        for part in parts:
            print("Sending %s" % part)
            s.sendall(part)
            time.sleep(0.5)

        resp = s.recv(4096, socket.MSG_WAITALL)
        s.close()

        print "response", repr(resp)

        status = resp.splitlines(0)[0]
        if '400' in status:
            raise Exception('Got unwanted response: %s' % status)
