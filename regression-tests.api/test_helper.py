from __future__ import print_function
from datetime import datetime
import os
import requests
import unittest
import sqlite3
import subprocess
import sys

if sys.version_info[0] == 2:
    from urlparse import urljoin
else:
    from urllib.parse import urljoin

DAEMON = os.environ.get('DAEMON', 'authoritative')
PDNSUTIL_CMD = os.environ.get('PDNSUTIL_CMD', 'NOT_SET BUT_THIS MIGHT_BE_A_LIST').split(' ')
SQLITE_DB = os.environ.get('SQLITE_DB', 'pdns.sqlite3')
SDIG = os.environ.get('SDIG', 'sdig')
DNSPORT = os.environ.get('DNSPORT', '53')

class ApiTestCase(unittest.TestCase):

    def setUp(self):
        # TODO: config
        self.server_address = '127.0.0.1'
        self.webServerBasicAuthPassword = 'something'
        self.server_port = int(os.environ.get('WEBPORT', '5580'))
        self.server_url = 'http://%s:%s/' % (self.server_address, self.server_port)
        self.server_web_password = os.environ.get('WEBPASSWORD', 'MISSING')
        self.session = requests.Session()
        self.session.headers = {'X-API-Key': os.environ.get('APIKEY', 'changeme-key'), 'Origin': 'http://%s:%s' % (self.server_address, self.server_port)}

    def url(self, relative_url):
        return urljoin(self.server_url, relative_url)

    def assert_success_json(self, result):
        try:
            result.raise_for_status()
        except:
            print(result.content)
            raise
        self.assertEquals(result.headers['Content-Type'], 'application/json')

    def assert_error_json(self, result):
        self.assertTrue(400 <= result.status_code < 600, "Response has not an error code "+str(result.status_code))
        self.assertEquals(result.headers['Content-Type'], 'application/json', "Response status code "+str(result.status_code))

    def assert_success(self, result):
        try:
            result.raise_for_status()
        except:
            print(result.content)
            raise


def unique_zone_name():
    return 'test-' + datetime.now().strftime('%d%H%S%M%f') + '.org.'

def unique_tsigkey_name():
    return 'test-' + datetime.now().strftime('%d%H%S%M%f') + '-key'

def is_auth():
    return DAEMON == 'authoritative'


def is_recursor():
    return DAEMON == 'recursor'


def get_auth_db():
    """Return Connection to Authoritative backend DB."""
    return sqlite3.Connection(SQLITE_DB)


def get_db_records(zonename, qtype):
    with get_auth_db() as db:
        rows = db.execute("""
            SELECT name, type, content, ttl, ordername
            FROM records
            WHERE type = ? AND domain_id = (
                SELECT id FROM domains WHERE name = ?
            )""", (qtype, zonename.rstrip('.'))).fetchall()
        recs = [{'name': row[0], 'type': row[1], 'content': row[2], 'ttl': row[3], 'ordername': row[4]} for row in rows]
        print("DB Records:", recs)
        return recs


def pdnsutil(subcommand, *args):
    try:
        return subprocess.check_output(PDNSUTIL_CMD + [subcommand] + list(args), close_fds=True).decode('ascii')
    except subprocess.CalledProcessError as except_inst:
        raise RuntimeError("pdnsutil %s %s failed: %s" % (subcommand, args, except_inst.output.decode('ascii', errors='replace')))

def pdnsutil_rectify(zonename):
    """Run pdnsutil rectify-zone on the given zone."""
    pdnsutil('rectify-zone', zonename)

def sdig(*args):
    try:
        return subprocess.check_call([SDIG, '127.0.0.1', str(DNSPORT)] + list(args))
    except subprocess.CalledProcessError as except_inst:
        raise RuntimeError("sdig %s %s failed: %s" % (command, args, except_inst.output.decode('ascii', errors='replace')))

def get_db_tsigkeys(keyname):
    with get_auth_db() as db:
        rows = db.execute("""
            SELECT name, algorithm, secret
            FROM tsigkeys
            WHERE name = ?""", (keyname, )).fetchall()
        keys = [{'name': row[0], 'algorithm': row[1], 'secret': row[2]} for row in rows]
        print("DB TSIG keys:", keys)
        return keys

