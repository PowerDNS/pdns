#!/usr/bin/env python3

from pdns_unittest import Handler
from pdns.remotebackend import PipeConnector

connector = PipeConnector(Handler)
connector.run()
