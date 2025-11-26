#!/usr/bin/env python

import zmq
import json
import os
from pdns_unittest import Handler


def run(socket, handler):
    while True:
        message = socket.recv()
        try:
            message = json.loads(message.decode().strip())
            method = "do_%s" % message["method"].lower()
            args = message["parameters"]
            handler.result = False
            handler.log = []
            if callable(getattr(handler, method, None)):
                getattr(handler, method)(**args)
                result = json.dumps({"result": handler.result, "log": handler.log})
                socket.send(result.encode())
        except KeyboardInterrupt as e3:
            return
        except BrokenPipeError as e2:
            raise e2
        except Exception as e:
            print(e)
            socket.send(json.dumps({"result": False}).encode())


def main():
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("ipc:///tmp/remotebackend.0")
    handler = Handler()
    print("Listening on ipc:///tmp/remotebackend.0")

    try:
        run(socket, handler)
    except KeyboardInterrupt as e:
        pass

    os.unlink("/tmp/remotebackend.0")


main()
