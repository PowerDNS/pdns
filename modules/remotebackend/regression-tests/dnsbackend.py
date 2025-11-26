#!/usr/bin/env python

import http.server
import json
import re

from urllib.parse import parse_qsl, urlparse, unquote


class DNSBackendHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.handler = kwargs["handler"]
        super().__init__(*args)

    def url_to_args(self):
        url = urlparse(self.path)
        parts = list(map(unquote, url.path.split("/")))
        parts.pop(0)
        self.method = None

        if parts.pop(0) != "dns":
            return

        self.method = parts.pop(0).lower()
        self.args = {}

        if self.method == "lookup":
            self.args["qname"] = parts.pop(0)
            self.args["qtype"] = parts.pop(0)
        elif self.method == "list":
            self.args["id"] = int(parts.pop(0))
            self.args["zonename"] = parts.pop(0)
        elif self.method in ("getbeforeandafternamesabsolute", "getbeforeandafternames"):
            self.args["id"] = int(parts.pop(0))
            self.args["qname"] = parts.pop(0)
        elif self.method in ("getdomainmetadata", "setdomainmetadata"):
            self.args["name"] = parts.pop(0)
            self.args["kind"] = parts.pop(0)
        elif self.method == "getdomainkeys":
            self.args["name"] = parts.pop(0)
        elif self.method in ("removedomainkey", "activatedomainkey", "deactivatedomainkey"):
            self.args["id"] = int(parts.pop(0))
            self.args["name"] = parts.pop(0)
        elif self.method in (
            "adddomainkey",
            "gettsigkey",
            "getdomaininfo",
            "settsigkey",
            "deletetsigkey",
            "getalldomainmetadata",
        ):
            self.args["name"] = parts.pop(0)
        elif self.method == "setnotified":
            self.args["id"] = int(parts.pop(0))
        elif self.method == "feedents":
            self.args["id"] = int(parts.pop(0))
            self.args["trxid"] = int(parts.pop(0))
        elif self.method == "ismaster":
            self.args["name"] = parts.pop(0)
            self.args["ip"] = parts.pop(0)
        elif self.method in ("supermasterbackend", "createslavedomain"):
            self.args["ip"] = parts.pop(0)
            self.args["domain"] = parts.pop(0)
        elif self.method in ("feedents3", "starttransaction"):
            self.args["id"] = int(parts.pop(0))
            self.args["domain"] = parts.pop(0)
            self.args["trxid"] = int(parts.pop(0))
        elif self.method in ("feedrecord", "committransaction", "aborttransaction"):
            self.args["trxid"] = int(parts.pop(0))
        elif self.method == "replacerrset":
            self.args["id"] = int(parts.pop(0))
            self.args["qname"] = parts.pop(0)
            self.args["qtype"] = parts.pop(0)
        assert len(parts) == 0, parts

        self.parse_qsl(url.query)

    def parse_qsl(self, qs):
        res = {}
        for key, value in parse_qsl(qs):
            m = re.match(r"^(.*)\[(.*)\]\[(.*)\]", key)
            if m:
                k1 = m.group(1)
                k2 = int(m.group(2))
                k3 = m.group(3)
                if k1 not in res:
                    res[k1] = list({})
                while len(res[k1]) <= k2:
                    res[k1].append({})
                res[k1][k2][k3] = value
            else:
                m = re.match(r"^(.*)\[(.*)\]", key)
                if m:
                    k1 = m.group(1)
                    k2 = m.group(2)
                    if k1 not in res:
                        if k2 == "":
                            res[k1] = list()
                        else:
                            res[k1] = {}
                    if k2 == "":
                        res[k1].append(value)
                    else:
                        res[k1][k2] = value
                else:
                    res[key] = value
        self.args = self.args | res

    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.end_headers()
            self.wfile.write("pong".encode())
            return
        self.do_POST()

    def do_DELETE(self):
        self.do_POST()

    def do_PATCH(self):
        self.do_POST()

    def do_PUT(self):
        self.do_POST()

    def do_POST(self):
        self.url_to_args()

        if not self.method:
            self.send_error(404)
            return

        try:
            length = 0
            if "content-length" in self.headers:
                length = int(self.headers.get("content-length"))
            if length > 0:
                qs = self.rfile.read(length).decode()
                self.parse_qsl(qs)

            if self.method == "adddomainkey":
                self.args["key"] = {
                    "flags": self.args["flags"],
                    "active": self.args["active"],
                    "published": self.args["published"],
                    "content": self.args["content"],
                }
                del self.args["flags"]
                del self.args["active"]
                del self.args["published"]
                del self.args["content"]

            if "serial" in self.args:
                self.args["serial"] = int(self.args["serial"])

            method = "do_%s" % self.method

            self.handler.result = False
            self.handler.log = []

            if callable(getattr(self.handler, method, None)):
                getattr(self.handler, method)(**self.args)
                result = json.dumps({"result": self.handler.result, "log": self.handler.log}).encode()
                self.send_response(200)
                self.send_header("content-type", "text/javascript")
                self.send_header("content-length", len(result))
                self.end_headers()
                self.wfile.write(result)
            else:
                self.send_error(404, message=json.dumps({"error": "No such method"}))
        except BrokenPipeError as e2:
            raise e2
        except Exception as e:
            self.log_error("Exception handling request: %r", e)
            self.send_error(400, message=str(e))
            raise e
