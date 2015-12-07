from datetime import datetime
from pprint import pprint
import os
import requests
import urlparse
import unittest
import sqlite3

DAEMON = os.environ.get('DAEMON', 'authoritative')
SQLITE_DB = os.environ.get('SQLITE_DB', 'pdns.sqlite3')


class ApiTestCase(unittest.TestCase):

    def setUp(self):
        # TODO: config
        self.server_address = '127.0.0.1'
        self.server_port = int(os.environ.get('WEBPORT', '5580'))
        self.server_url = 'http://%s:%s/' % (self.server_address, self.server_port)
        self.session = requests.Session()
        self.session.headers = {'X-API-Key': os.environ.get('APIKEY', 'changeme-key'), 'Origin': 'http://%s:%s' % (self.server_address, self.server_port)}

    def url(self, relative_url):
        return urlparse.urljoin(self.server_url, relative_url)

    def assert_success_json(self, result):
        try:
            result.raise_for_status()
        except:
            print result.content
            raise
        self.assertEquals(result.headers['Content-Type'], 'application/json')


def unique_zone_name():
    return 'test-' + datetime.now().strftime('%d%H%S%M%f') + '.org.'


def is_auth():
    return DAEMON == 'authoritative'


def is_recursor():
    return DAEMON == 'recursor'


def eq_zone_dict(rrsets, expected):
    data_got = {}
    data_expected = {}
    for type_, expected_records in expected.iteritems():
        type_ = str(type_)
        uses_name = any(['name' in expected_record for expected_record in expected_records])
        # minify + convert received data
        data_got[type_] = set((str(rec['name']) if uses_name else '@', str(rec['content']))
                              for rec in rrsets if rec['type'] == type_)
        # minify expected data
        data_expected[type_] = set((str(rec['name']) if uses_name else '@', str(rec['content']))
                                   for rec in expected_records)

    print "eq_zone_dict: got:"
    pprint(data_got)
    print "eq_zone_dict: expected:"
    pprint(data_expected)

    assert data_got == data_expected, "%r != %r" % (data_got, data_expected)


def get_auth_db():
    """Return Connection to Authoritative backend DB."""
    return sqlite3.Connection(SQLITE_DB)


def get_db_records(zonename, qtype):
    with get_auth_db() as db:
        rows = db.execute("""
            SELECT name, type, content, ttl
            FROM records
            WHERE type = ? AND domain_id = (
                SELECT id FROM domains WHERE name = ?
            )""", (qtype, zonename.rstrip('.'))).fetchall()
        recs = [{'name': row[0], 'type': row[1], 'content': row[2], 'ttl': row[3]} for row in rows]
        print "DB Records:", recs
        return recs
