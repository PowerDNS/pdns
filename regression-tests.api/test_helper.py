from __future__ import print_function
from datetime import datetime
import os
import requests
import unittest
import mysql.connector
import psycopg2
import sqlite3
import subprocess
import sys

if sys.version_info[0] == 2:
    from urlparse import urljoin
else:
    from urllib.parse import urljoin

DAEMON = os.environ.get("DAEMON", "authoritative")
PDNSUTIL_CMD = os.environ.get("PDNSUTIL_CMD", "NOT_SET BUT_THIS MIGHT_BE_A_LIST").split(" ")
BACKEND = os.environ.get("BACKEND", "gsqlite3")
MYSQL_DB = os.environ.get("MYSQL_DB", "pdnsapi")
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PASSWD = os.environ.get("MYSQL_PASWORD", "")
PGSQL_DB = os.environ.get("PGSQL_DB", "pdnsapi")
SQLITE_DB = os.environ.get("SQLITE_DB", "pdns.sqlite3")
LMDB_DB = os.environ.get("SQLITE_DB", "pdns.lmdb")
SDIG = os.environ.get("SDIG", "sdig")
DNSPORT = os.environ.get("DNSPORT", "53")


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        # TODO: config
        self.server_address = "127.0.0.1"
        self.webServerBasicAuthPassword = "something"
        self.server_port = int(os.environ.get("WEBPORT", "5580"))
        self.server_url = "http://%s:%s/" % (self.server_address, self.server_port)
        self.server_web_password = os.environ.get("WEBPASSWORD", "MISSING")
        self.session = requests.Session()
        self.session.headers = {
            "X-API-Key": os.environ.get("APIKEY", "changeme-key"),
            "Origin": "http://%s:%s" % (self.server_address, self.server_port),
        }
        if is_recursor():
            self.server_url = "https://%s:%s/" % (self.server_address, self.server_port)
            self.session.verify = "ca.pem"

    def url(self, relative_url):
        return urljoin(self.server_url, relative_url)

    def assert_success_json(self, result):
        try:
            result.raise_for_status()
        except Exception:
            print(result.content)
            raise
        self.assertEqual(result.headers["Content-Type"], "application/json")

    def assert_error_json(self, result):
        self.assertTrue(400 <= result.status_code < 600, "Response has not an error code " + str(result.status_code))
        self.assertEqual(
            result.headers["Content-Type"], "application/json", "Response status code " + str(result.status_code)
        )

    def assert_success(self, result):
        try:
            result.raise_for_status()
        except Exception:
            print(result.content)
            raise


def unique_zone_name():
    return "test-" + datetime.now().strftime("%d%H%S%M%f") + ".org."


def unique_tsigkey_name():
    return "test-" + datetime.now().strftime("%d%H%S%M%f") + "-key"


def is_auth():
    return DAEMON == "authoritative"


def is_auth_lmdb():
    return DAEMON == "authoritative" and BACKEND == "lmdb"


def is_recursor():
    return DAEMON == "recursor"


def get_auth_db():
    """Return Connection to Authoritative backend DB."""
    if BACKEND == "gmysql":
        return mysql.connector.connect(database=MYSQL_DB, user=MYSQL_USER, host=MYSQL_HOST, password=MYSQL_PASSWD), "%s"
    elif BACKEND == "gpgsql":
        return psycopg2.connect(database=PGSQL_DB), "%s"
    else:
        return sqlite3.Connection(SQLITE_DB), "?"


def get_db_records(zonename, qtype):
    db, placeholder = get_auth_db()
    cur = db.cursor()
    cur.execute(
        """
        SELECT name, type, content, ttl, ordername
        FROM records
        WHERE type = """
        + placeholder
        + """ AND domain_id = (
            SELECT id FROM domains WHERE name = """
        + placeholder
        + """
        )""",
        (qtype, zonename.rstrip(".")),
    )
    rows = cur.fetchall()
    cur.close()
    db.close()
    recs = [{"name": row[0], "type": row[1], "content": row[2], "ttl": row[3], "ordername": row[4]} for row in rows]
    print("DB Records:", recs)
    return recs


def pdnsutil(subcommand, *args):
    try:
        return subprocess.check_output(PDNSUTIL_CMD + [subcommand] + list(args), close_fds=True).decode("ascii")
    except subprocess.CalledProcessError as except_inst:
        raise RuntimeError(
            "pdnsutil %s %s failed: %s" % (subcommand, args, except_inst.output.decode("ascii", errors="replace"))
        )


def pdnsutil_rectify(zonename):
    """Run pdnsutil rectify-zone on the given zone."""
    pdnsutil("rectify-zone", zonename)


def sdig(*args):
    if is_auth():
        sdig_command_line = [SDIG, "127.0.0.1", str(DNSPORT)] + list(args)
    else:
        sdig_command_line = [SDIG, "127.0.0.1", str(DNSPORT)] + list(args) + ["recurse"]
    try:
        return subprocess.check_output(sdig_command_line).decode("utf-8")
    except subprocess.CalledProcessError as except_inst:
        raise RuntimeError(
            "sdig %s failed: %s" % (sdig_command_line, except_inst.output.decode("ascii", errors="replace"))
        )
