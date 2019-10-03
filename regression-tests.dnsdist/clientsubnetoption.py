#!/usr/bin/env python
#
# Copyright (c) 2012 OpenDNS, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the OpenDNS nor the names of its contributors may be
#      used to endorse or promote products derived from this software without
#      specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL OPENDNS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

""" Class to implement draft-ietf-dnsop-edns-client-subnet (previously known as
draft-vandergaast-edns-client-subnet.

The contained class supports both IPv4 and IPv6 addresses.
Requirements:
  dnspython (http://www.dnspython.org/)
"""
from __future__ import print_function
from __future__ import division

import socket
import struct
import dns
import dns.edns
import dns.flags
import dns.message
import dns.query

__author__ = "bhartvigsen@opendns.com (Brian Hartvigsen)"
__version__ = "2.0.0"

ASSIGNED_OPTION_CODE = 0x0008
DRAFT_OPTION_CODE = 0x50FA

FAMILY_IPV4 = 1
FAMILY_IPV6 = 2
SUPPORTED_FAMILIES = (FAMILY_IPV4, FAMILY_IPV6)


class ClientSubnetOption(dns.edns.Option):
    """Implementation of draft-vandergaast-edns-client-subnet-01.

    Attributes:
        family: An integer indicating which address family is being sent
        ip: IP address in integer notation
        mask: An integer representing the number of relevant bits being sent
        scope: An integer representing the number of significant bits used by
            the authoritative server.
    """

    def __init__(self, ip, bits=24, scope=0, option=ASSIGNED_OPTION_CODE):
        super(ClientSubnetOption, self).__init__(option)

        n = None
        f = None

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                n = socket.inet_pton(family, ip)
                if family == socket.AF_INET6:
                    f = FAMILY_IPV6
                    hi, lo = struct.unpack('!QQ', n)
                    ip = hi << 64 | lo
                elif family == socket.AF_INET:
                    f = FAMILY_IPV4
                    ip = struct.unpack('!L', n)[0]
            except Exception:
                pass

        if n is None:
            raise Exception("%s is an invalid ip" % ip)

        self.family = f
        self.ip = ip
        self.mask = bits
        self.scope = scope
        self.option = option

        if self.family == FAMILY_IPV4 and self.mask > 32:
            raise Exception("32 bits is the max for IPv4 (%d)" % bits)
        if self.family == FAMILY_IPV6 and self.mask > 128:
            raise Exception("128 bits is the max for IPv6 (%d)" % bits)

    def calculate_ip(self):
        """Calculates the relevant ip address based on the network mask.

        Calculates the relevant bits of the IP address based on network mask.
        Sizes up to the nearest octet for use with wire format.

        Returns:
            An integer of only the significant bits sized up to the nearest
            octect.
        """

        if self.family == FAMILY_IPV4:
            bits = 32
        elif self.family == FAMILY_IPV6:
            bits = 128

        ip = self.ip >> bits - self.mask

        if (self.mask % 8 != 0):
            ip = ip << 8 - (self.mask % 8)

        return ip

    def is_draft(self):
        """" Determines whether this instance is using the draft option code """
        return self.option == DRAFT_OPTION_CODE

    def to_wire(self, file):
        """Create EDNS packet as defined in draft-vandergaast-edns-client-subnet-01."""

        ip = self.calculate_ip()

        mask_bits = self.mask
        if mask_bits % 8 != 0:
                mask_bits += 8 - (self.mask % 8)

        if self.family == FAMILY_IPV4:
            test = struct.pack("!L", ip)
        elif self.family == FAMILY_IPV6:
            test = struct.pack("!QQ", ip >> 64, ip & (2 ** 64 - 1))
        test = test[-(mask_bits // 8):]

        format = "!HBB%ds" % (mask_bits // 8)
        data = struct.pack(format, self.family, self.mask, self.scope, test)
        file.write(data)

    def from_wire(cls, otype, wire, current, olen):
        """Read EDNS packet as defined in draft-vandergaast-edns-client-subnet-01.

        Returns:
            An instance of ClientSubnetOption based on the ENDS packet
        """

        data = wire[current:current + olen]
        (family, mask, scope) = struct.unpack("!HBB", data[:4])

        c_mask = mask
        if mask % 8 != 0:
            c_mask += 8 - (mask % 8)

        ip = struct.unpack_from("!%ds" % (c_mask // 8), data, 4)[0]

        if (family == FAMILY_IPV4):
            ip = ip + b'\0' * ((32 - c_mask) // 8)
            ip = socket.inet_ntop(socket.AF_INET, ip)
        elif (family == FAMILY_IPV6):
            ip = ip + b'\0' * ((128 - c_mask) // 8)
            ip = socket.inet_ntop(socket.AF_INET6, ip)
        else:
            raise Exception("Returned a family other then IPv4 or IPv6")

        return cls(ip, mask, scope, otype)

    from_wire = classmethod(from_wire)

    def __repr__(self):
        if self.family == FAMILY_IPV4:
            ip = socket.inet_ntop(socket.AF_INET, struct.pack('!L', self.ip))
        elif self.family == FAMILY_IPV6:
            ip = socket.inet_ntop(socket.AF_INET6,
                                  struct.pack('!QQ',
                                              self.ip >> 64,
                                              self.ip & (2 ** 64 - 1)))

        return "%s(%s, %s, %s)" % (
            self.__class__.__name__,
            ip,
            self.mask,
            self.scope
        )

    def to_text(self):
        return self.__repr__()

    def __eq__(self, other):
        """Rich comparison method for equality.

        Two ClientSubnetOptions are equal if their relevant ip bits, mask, and
        family are identical. We ignore scope since generally we want to
        compare questions to responses and that bit is only relevant when
        determining caching behavior.

        Returns:
            boolean
        """

        if not isinstance(other, ClientSubnetOption):
            return False
        if self.calculate_ip() != other.calculate_ip():
            return False
        if self.mask != other.mask:
            return False
        if self.family != other.family:
            return False
        return True

    def __ne__(self, other):
        """Rich comparison method for inequality.

        See notes for __eq__()

        Returns:
            boolean
        """
        return not self.__eq__(other)


dns.edns._type_to_class[DRAFT_OPTION_CODE] = ClientSubnetOption
dns.edns._type_to_class[ASSIGNED_OPTION_CODE] = ClientSubnetOption

if __name__ == "__main__":
    import argparse
    import sys

    def CheckForClientSubnetOption(addr, args, option_code=ASSIGNED_OPTION_CODE):
        print("Testing for edns-clientsubnet using option code", hex(option_code), file=sys.stderr)
        cso = ClientSubnetOption(args.subnet, args.mask, option=option_code)
        message = dns.message.make_query(args.rr, args.type)
        # Tested authoritative servers seem to use the last code in cases
        # where they support both. We make the official code last to allow
        # us to check for support of both draft and official
        message.use_edns(options=[cso])

        try:
            r = dns.query.udp(message, addr, timeout=args.timeout)
            if r.flags & dns.flags.TC:
                r = dns.query.tcp(message, addr, timeout=args.timeout)
        except dns.exception.Timeout:
            print("Timeout: No answer received from %s\n" % args.nameserver, file=sys.stderr)
            sys.exit(3)

        error = False
        found = False
        for options in r.options:
            # Have not run into anyone who passes back both codes yet
            # but just in case, we want to check all possible options
            if isinstance(options, ClientSubnetOption):
                found = True
                print("Found ClientSubnetOption...", end=None, file=sys.stderr)
                if not cso.family == options.family:
                    error = True
                    print("\nFailed: returned family (%d) is different from the passed family (%d)" % (options.family, cso.family), file=sys.stderr)
                if not cso.calculate_ip() == options.calculate_ip():
                    error = True
                    print("\nFailed: returned ip (%s) is different from the passed ip (%s)." % (options.calculate_ip(), cso.calculate_ip()), file=sys.stderr)
                if not options.mask == cso.mask:
                    error = True
                    print("\nFailed: returned mask bits (%d) is different from the passed mask bits (%d)" % (options.mask, cso.mask), file=sys.stderr)
                if not options.scope != 0:
                    print("\nWarning: scope indicates edns-clientsubnet data is not used", file=sys.stderr)
                if options.is_draft():
                    print("\nWarning: detected support for edns-clientsubnet draft code", file=sys.stderr)

        if found and not error:
            print("Success", file=sys.stderr)
        elif found:
            print("Failed: See error messages above", file=sys.stderr)
        else:
            print("Failed: No ClientSubnetOption returned", file=sys.stderr)

    parser = argparse.ArgumentParser(description='draft-vandergaast-edns-client-subnet-01 tester')
    parser.add_argument('nameserver', help='The nameserver to test')
    parser.add_argument('rr', help='DNS record that should return an EDNS enabled response')
    parser.add_argument('-s', '--subnet', help='Specifies an IP to pass as the client subnet.', default='192.0.2.0')
    parser.add_argument('-m', '--mask', type=int, help='CIDR mask to use for subnet')
    parser.add_argument('--timeout', type=int, help='Set the timeout for query to TIMEOUT seconds, default=10', default=10)
    parser.add_argument('-t', '--type', help='DNS query type, default=A', default='A')
    args = parser.parse_args()

    if not args.mask:
        if ':' in args.subnet:
            args.mask = 48
        else:
            args.mask = 24

    try:
        addr = socket.gethostbyname(args.nameserver)
    except socket.gaierror:
        print("Unable to resolve %s\n" % args.nameserver, file=sys.stderr)
        sys.exit(3)

    CheckForClientSubnetOption(addr, args, DRAFT_OPTION_CODE)
    print("", file=sys.stderr)
    CheckForClientSubnetOption(addr, args, ASSIGNED_OPTION_CODE)
