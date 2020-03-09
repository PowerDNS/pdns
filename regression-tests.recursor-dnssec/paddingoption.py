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

    def to_wire(self, file):
        """Create EDNS packet as defined in rfc7830."""

        file.write(bytes(self.numberOfBytes))

    def from_wire(cls, otype, wire, current, olen):
        """Read EDNS packet as defined in rfc7830.

        Returns:
            An instance of PaddingOption based on the EDNS packet
        """

        numberOfBytes = olen

        return cls(numberOfBytes)

    from_wire = classmethod(from_wire)

    def __repr__(self):
        return '%s(%d)' % (
            self.__class__.__name__,
            self.numberOfBytes
        )

    def __eq__(self, other):
        if not isinstance(other, PaddingOption):
            return False
        return self.numberOfBytes == numberOfBytes

    def __ne__(self, other):
        return not self.__eq__(other)


dns.edns._type_to_class[0x000C] = PaddingOption
