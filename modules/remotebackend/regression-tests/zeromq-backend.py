#!/usr/bin/env python

import zmq
import json
import os
from urllib.parse import parse_qs, urlparse
from backend import BackendHandler

def run(socket, handler):
    while True:
        message = socket.recv()
        try:
            message = json.loads(message.decode().strip())
            method = "do_%s" % message['method'].lower()
            args = message['parameters']
            handler.result = False
            handler.log = []
            if callable(getattr(handler, method, None)):
                getattr(handler, method)(**args)
                result = json.dumps({'result': handler.result,'log': handler.log})
                socket.send(result.encode())
        except KeyboardInterrupt as e3:
            return
        except BrokenPipeError as e2:
            raise e2
        except Exception as e:
            print(e)
            socket.send(json.dumps({'result':False}).encode())


def main():
    path = os.path.dirname(os.path.realpath(__file__))
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("ipc:///tmp/pdns.0")
    handler = BackendHandler(options={'dbpath': os.path.join(path, 'remote.sqlite3')})

    try:
        run(socket, handler)
    except KeyboardInterrupt as e:
        pass

    os.unlink("/tmp/remotebackend.0")
 
main()
