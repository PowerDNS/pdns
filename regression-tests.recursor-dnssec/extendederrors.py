#!/usr/bin/env python
import struct

import dns
import dns.edns
import dns.flags
import dns.message
import dns.query

class ExtendedErrorOption(dns.edns.Option):
    """Implementation of rfc8914
    """

    def __init__(self, code, extra):
        super(ExtendedErrorOption, self).__init__(15)

        self.code = code
        self.extra = extra

    def to_wire(self, file=None):
        """Create EDNS packet."""

        data = struct.pack('!H', self.code)
        data = data + self.extra
        if not file:
            return data
        file.write(data)
        return None

    def from_wire(self, otype, wire, current, olen):
        """Read EDNS packet.

        Returns:
            An instance of ExtendedErrorOption based on the EDNS packet
        """

        if olen < 2:
            raise Exception('Invalid EDNS Extended Error option')

        (code,) = struct.unpack('!H', wire[current:current+2])
        if olen > 2:
            extra = wire[current + 2:current + olen]
        else:
            extra = b''

        return self(code, extra)

    from_wire = classmethod(from_wire)

    # needed in 2.0.0
    @classmethod
    def from_wire_parser(cls, otype, parser):
        data = parser.get_remaining()

        if len(data) < 2:
            raise Exception('Invalid EDNS Extended Error option')

        (code,) = struct.unpack('!H', data[0:2])
        if len(data) > 2:
            extra = data[2:]
        else:
            extra = b''

        return cls(code, extra)

    def __repr__(self):
        return '%s(%d, %s)' % (
            self.__class__.__name__,
            self.code,
            self.extra
        )

    def to_text(self):
        return self.__repr__()

    def __eq__(self, other):
        if not isinstance(other, ExtendedErrorOption):
            return False
        if self.code != other.code:
            return False
        if self.extra != other.extra:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)


dns.edns._type_to_class[0x000F] = ExtendedErrorOption
