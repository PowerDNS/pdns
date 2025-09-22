#!/usr/bin/env python

import dns
import dns.edns
import dns.flags
import dns.message
import dns.query

class PaddingOption(dns.edns.Option):
    """Implementation of rfc7830.
    """

    def __init__(self, numberOfBytes):
        super(PaddingOption, self).__init__(12)
        self.numberOfBytes = numberOfBytes

    def to_wire(self, file=None):
        """Create EDNS packet as defined in rfc7830."""

        if file:
            file.write(bytes(self.numberOfBytes))
        else:
            return bytes(self.numberOfBytes)

    def from_wire(cls, otype, wire, current, olen):
        """Read EDNS packet as defined in rfc7830.

        Returns:
            An instance of PaddingOption based on the EDNS packet
        """

        numberOfBytes = olen

        return cls(numberOfBytes)

    from_wire = classmethod(from_wire)

    # needed in 2.0.0
    @classmethod
    def from_wire_parser(cls, otype, parser):
        data = parser.get_remaining()
        return cls(len(data))

    def __repr__(self):
        return '%s(%d)' % (
            self.__class__.__name__,
            self.numberOfBytes
        )

    def to_text(self):
        return self.__repr__()

    def __eq__(self, other):
        if not isinstance(other, PaddingOption):
            return False
        return self.numberOfBytes == numberOfBytes

    def __ne__(self, other):
        return not self.__eq__(other)


dns.edns._type_to_class[0x000C] = PaddingOption
