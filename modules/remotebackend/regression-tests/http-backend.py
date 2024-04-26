#!/usr/bin/env python

import http.server
from backend import BackendHandler
from dnsbackend import DNSBackendHandler
import os

class DNSBackendServer(http.server.HTTPServer):
    def __init__(self, *args, **kwargs):
        path = os.path.dirname(os.path.realpath(__file__))
        self.handler = BackendHandler(options={'dbpath': os.path.join(path, 'remote.sqlite3')})
        super().__init__(*args, **kwargs)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        h = self.RequestHandlerClass(request, client_address, self, handler=self.handler)

def main():
    server = DNSBackendServer(('', 62434), DNSBackendHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

main()
