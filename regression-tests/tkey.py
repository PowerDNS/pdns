#!/usr/bin/env python

import socket
import select
import sys

def ensure(data, offset, value):
  if (data[offset:offset+len(value)] != value):
    raise Exception("Mismatch at packet offset {0!s} {1!r} != {2!r}".format(offset,data[offset:offset+len(value)], value))

def main(host, port):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  msg = "\xaa\x77\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x04tkey\x04unit\x04test\x00\x00\xf9\x00\xff\x04tkey\x04unit\x04test\x00\x00\xf9\x00\xff\x00\x00\x00\x00\x00\x22\x03bad\04algo\x00\x00\x00\x30\x39\x00\x00\x30\x39\x00\x03\x00\x00\x00\x04test\x00\x00"

  s.sendto(msg, (host, port))
  s.settimeout(2)
  data, addr = s.recvfrom(512)

  # make sure the data validates

  # transaction id
  ensure(data, 0, msg[0:2])

  # has one question, one answer
  ensure(data, 4, "\x00\x01")
  ensure(data, 6, "\x00\x01")

  # question is tkey.unit.test ANY TKEY?
  ensure(data, 12, "\x04tkey\x04unit\x04test\x00\x00\xf9\x00\xff")
  # answer is called tkey.unit.test ANY TKEY (compressed it seems)
  ensure(data, 32, "\xc0\x0c\x00\xf9\x00\xff")

  # and then ensure we get an BADALGO or error, at least.
  if (data[64:66] == "\x00\x00"):
    raise Exception("At packet offset {0!s}: expected {2!r}, got {1!r}".format(offset,data[offset:offset+len(value)], value))

  print "Got expected TKEY response\n"

if (len(sys.argv) < 3):
  print "Usage: tkey.py host port"
  sys.exit(1)

if __name__ == '__main__':
  main(sys.argv[1], int(sys.argv[2]))
