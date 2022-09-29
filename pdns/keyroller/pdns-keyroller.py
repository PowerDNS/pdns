#!/usr/bin/env python3
import argparse
import logging
import pdnskeyroller.daemon
import sys
import traceback

logger = logging.getLogger('pdns-keyroller')

if __name__ == '__main__':
    argp = argparse.ArgumentParser(
        prog='pdns-keyroller', formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='PowerDNS DNSSEC key-roller daemon')
    argp.add_argument('--verbose', '-v', action='count', help='Be more verbose')
    argp.add_argument('--config', '-c', metavar='PATH', type=str, default='/etc/powerdns/pdns-keyroller.conf',
                      help='Load this configuration file')

    arguments = argp.parse_args()

    if arguments.verbose:
        if arguments.verbose == 1:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.DEBUG)

    d = None
    try:
        d = pdnskeyroller.daemon.Daemon(arguments.config)
    except ConnectionError as e:
        logger.fatal('Unable to start: {}'.format(e))
        sys.exit(1)

    try:
        d.run()
    except Exception as e:
        print(traceback.extract_tb(e))
        logger.error("Unable to run: {}".format(e))
