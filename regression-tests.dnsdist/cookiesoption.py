#!/usr/bin/env python2

import dns
import dns.edns
import dns.flags
import dns.message
import dns.query

class CookiesOption(dns.edns.Option):
    """Implementation of draft-ietf-dnsop-cookies-09.
    """

    def __init__(self, client, server):
        super(CookiesOption, self).__init__(10)

        if len(client) != 8:
            raise Exception('invalid client cookie length')

        if server is not None and len(server) != 0 and (len(server) < 8 or len(server) > 32):
            raise Exception('invalid server cookie length')

        self.client = client
        self.server = server

    def to_wire(self, file):
        """Create EDNS packet as defined in draft-ietf-dnsop-cookies-09."""

        file.write(self.client)
        if self.server and len(self.server) > 0:
            file.write(self.server)

    def from_wire(cls, otype, wire, current, olen):
        """Read EDNS packet as defined in draft-ietf-dnsop-cookies-09.

        Returns:
            An instance of CookiesOption based on the EDNS packet
        """

        data = wire[current:current + olen]
        if len(data) != 8 and (len(data) < 16 or len(data) > 40):
            raise Exception('Invalid EDNS Cookies option')

        client = data[:8]
        if len(data) > 8:
            server = data[8:]
        else:
            server = None

        return cls(client, server)

    from_wire = classmethod(from_wire)

    def __repr__(self):
        return '%s(%s, %s)' % (
            self.__class__.__name__,
            self.client,
            self.server
        )

    def to_text(self):
        return self.__repr__()

    def __eq__(self, other):
        if not isinstance(other, CookiesOption):
            return False
        if self.client != other.client:
            return False
        if self.server != other.server:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)


dns.edns._type_to_class[0x000A] = CookiesOption

