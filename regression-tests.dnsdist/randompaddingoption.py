#!/usr/bin/env python
import os
import paddingoption


class RandomPaddingOption(paddingoption.PaddingOption):
    """Implementation of rfc7830 using random bytes in the payload."""

    def __init__(self, numberOfBytes):
        super(RandomPaddingOption, self).__init__(12)
        self.numberOfBytes = numberOfBytes

    def to_wire(self, file=None):
        """Create EDNS packet as defined in rfc7830 using random bytes in the payload."""

        payload = os.urandom(self.numberOfBytes)
        if not file:
            return payload
        file.write(payload)
        return None
