#!/usr/bin/env python

import http.server
import json
from urllib.parse import parse_qs, urlparse
from pdns_unittest import Handler


class DNSBackendServer(http.server.HTTPServer):
    def __init__(self, *args, **kwargs):
        self.handler = Handler()
        super().__init__(*args, **kwargs)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        h = self.RequestHandlerClass(request, client_address, self, handler=self.handler)


class DNSBackendHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.handler = kwargs['handler']
        super().__init__(*args)

    def do_GET(self):
        if self.path == '/ping':
            self.send_response(200)
            self.end_headers()
            self.wfile.write("pong".encode())
            return
        self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith('/dns/'):
            self.send_error(404)
            return

        try:
            length = int(self.headers.get('content-length'))
            args = json.loads(parse_qs(self.rfile.read(length).decode())['parameters'][0])
            method = "do_%s" % path[5:].lower()
            self.log_error("%r", args)

            self.handler.result = False
            self.handler.log = []

            if callable(getattr(self.handler, method, None)):
                getattr(self.handler, method)(**args)
                result = json.dumps({'result':self.handler.result,'log':self.handler.log}).encode()

                self.send_response(200)
                self.send_header("content-type", "text/javascript");
                self.send_header("content-length", len(result))
                self.end_headers()
                self.wfile.write(result)
            else:
                self.send_error(404, message=json.dumps({'error': 'No such method'}))
        except BrokenPipeError as e2:
            raise e2
        except Exception as e:
            self.send_error(400, message=str(e))


def main():
    server = DNSBackendServer(('', 62434), DNSBackendHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

main()
