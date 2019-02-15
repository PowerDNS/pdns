import requests
import socket
import time
from test_helper import ApiTestCase


class TestBasics(ApiTestCase):

    def test_unauth(self):
        r = requests.get(self.url("/api/v1/servers/localhost"))
        self.assertEquals(r.status_code, requests.codes.unauthorized)

    def test_index_html(self):
        r = requests.get(self.url("/"), auth=('admin', self.server_web_password))
        self.assertEquals(r.status_code, requests.codes.ok)

    def test_split_request(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((self.server_address, self.server_port))

        parts = ("GET / HTTP/1.0\r\n", "Content-Type: text/plain\r\n\r\n")

        print("Sending request")
        for part in parts:
            print("Sending %s" % part)
            s.sendall(part.encode('ascii'))
            time.sleep(0.5)

        resp = s.recv(4096, socket.MSG_WAITALL)
        s.close()

        print("response", repr(resp))

        status = resp.splitlines(0)[0]
        if b'400' in status:
            raise Exception('Got unwanted response: %s' % status)

    def test_cors(self):
        r = self.session.options(self.url("/api/v1/servers/localhost"))
        # look for CORS headers

        self.assertEquals(r.status_code, requests.codes.ok)
        self.assertEquals(r.headers['access-control-allow-origin'], "*")
        self.assertEquals(r.headers['access-control-allow-headers'], 'Content-Type, X-API-Key')
        self.assertEquals(r.headers['access-control-allow-methods'], 'GET, POST, PUT, PATCH, DELETE, OPTIONS')

        print("response", repr(r.headers))
