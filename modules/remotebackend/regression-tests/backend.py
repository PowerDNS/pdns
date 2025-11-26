#!/usr/bin/env python

import sqlite3
from pdns.remotebackend import Handler


class BackendHandler(Handler):
    def __init__(self, options={}):
        super().__init__(options=options)
        self.dbpath = options["dbpath"]
        self.db = sqlite3.connect(self.dbpath)

    def get_domain_id(self, name):
        cur = self.db.execute("SELECT id FROM domains WHERE name = ?", (name,))
        row = cur.fetchone()
        if not row:
            self.result = False
            raise KeyError
        return int(row[0])

    def record(self, qname="", qtype="", content="", ttl=1, prio=0, auth=1, domain_id=-1):
        """Generate one record"""
        if ttl == -1:
            ttl = self.ttl
        if qtype in ("MX", "SRV"):
            content = "%d %s" % (prio, content)
        return {"qtype": qtype, "qname": qname, "content": content, "ttl": ttl, "auth": auth, "domain_id": domain_id}

    # ends up here as qname=qname, id=id
    def getbeforename(self, **kwargs):
        cur = self.db.execute(
            "SELECT ordername FROM records WHERE ordername < :qname AND domain_id = :id ORDER BY ordername DESC LIMIT 1",
            kwargs,
        )
        row = cur.fetchone()
        if not row:
            cur = self.db.execute(
                "SELECT ordername FROM records WHERE domain_id = :id ORDER by ordername DESC LIMIT 1", kwargs
            )
            row = cur.fetchone()
        result = row[0]
        if row[0] is None:
            result = ""
        return result

    def getaftername(self, **kwargs):
        cur = self.db.execute(
            "SELECT ordername FROM records WHERE ordername > :qname AND domain_id = :id ORDER BY ordername LIMIT 1",
            kwargs,
        )
        row = cur.fetchone()
        if row is None:
            cur = self.db.execute(
                "SELECT ordername FROM records WHERE domain_id = :id ORDER by ordername LIMIT 1", kwargs
            )
            row = cur.fetchone()
        result = row[0]
        if row[0] is None:
            result = ""
        return result

    def do_getbeforeandafternamesabsolute(self, **kwargs):
        self.result = {
            "before": self.getbeforename(**kwargs),
            "after": self.getaftername(**kwargs),
            "unhashed": kwargs["qname"],
        }

    def do_getbeforeandafternames(self, **kwargs):
        self.do_getbeforeandafternamesabsolute(**kwargs)

    def do_getdomainkeys(self, name, **kwargs):
        self.result = []
        cur = self.db.execute(
            "SELECT cryptokeys.id, flags, active, published, content FROM domains JOIN cryptokeys ON domains.id = cryptokeys.domain_id WHERE domains.name = :name",
            {"name": name},
        )
        for row in cur.fetchall():
            self.result.append(
                {"id": row[0], "flags": row[1], "active": row[2] != 0, "published": row[3], "content": row[4]}
            )
        if len(self.result) == 0:
            self.result = False
        self.log.append(self.dbpath)

    def do_lookup(self, qname="", qtype="", domain_id=-1, **kwargs):
        self.result = []
        if kwargs.get("zone-id", -1) > 0:
            domain_id = kwargs["zone-id"]
        if domain_id > -1:
            if qtype == "ANY":
                sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname AND domain_id = :domain_id"
            else:
                sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname AND type = :qtype AND domain_id = :domain_id"
        else:
            if qtype == "ANY":
                sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname"
            else:
                sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname AND type = :qtype"
        cur = self.db.execute(sql, {"qname": qname, "qtype": qtype, "domain_id": domain_id})
        for row in cur.fetchall():
            self.result.append(
                self.record(
                    qname=row[1], qtype=row[2], content=row[3], ttl=row[4], prio=row[5], auth=row[6], domain_id=row[0]
                )
            )

    def do_getdomaininfo(self, name="", **kwargs):
        self.result = False
        cur = self.db.execute(
            "SELECT domain_id,name,content FROM records WHERE name = :name AND type = 'SOA'", {"name": name}
        )
        for row in cur.fetchall():
            self.result = {
                "zone": row[1],
                "serial": int(row[2].split(" ")[2]),
                "kind": "native",
                "id": row[0],
            }

    def do_getalldomains(self):
        self.result = []
        cur = self.db.execute(
            "SELECT domain_id,name,content FROM records WHERE name = :name AND type = 'SOA'", {"name": name}
        )
        for row in cur.fetchall():
            self.result.append(
                {
                    "zone": row[1],
                    "serial": int(row[2].split(" ")[2]),
                    "kind": "native",
                    "id": row[0],
                }
            )

    def do_list(self, zonename="", domain_id=-1, **kwargs):
        if domain_id == -1:
            try:
                domain_id = self.get_domain_id(zonename)
            except KeyError:
                return
        if domain_id > -1:
            self.result = []
            cur = self.db.execute(
                "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE domain_id = ?", (domain_id,)
            )
            for row in cur.fetchall():
                self.result.append(
                    self.record(
                        qname=row[1],
                        qtype=row[2],
                        content=row[3],
                        ttl=row[4],
                        prio=row[5],
                        auth=row[6],
                        domain_id=row[0],
                    )
                )

    def do_adddomainkey(self, name, key, **kwargs):
        try:
            domain_id = self.get_domain_id(name)
        except KeyError:
            return
        key["domain_id"] = domain_id

        cur = self.db.execute(
            "INSERT INTO cryptokeys (domain_id, flags, active, published, content) VALUES(:domain_id, :flags, :active, :published, :content)",
            key,
        )
        self.db.commit()

        self.result = cur.lastrowid
        self.log.append(self.dbpath)

    def do_deactivatedomainkey(self, **kwargs):
        try:
            domain_id = self.get_domain_id(kwargs["name"])
        except KeyError:
            return
        kwargs["domain_id"] = domain_id

        self.db.execute("UPDATE cryptokeys SET active = 0 WHERE domain_id = :domain_id AND id = :id", kwargs)
        self.db.commit()

        self.result = True

    def do_activatedomainkey(self, **kwargs):
        try:
            domain_id = self.get_domain_id(kwargs["name"])
        except KeyError:
            return
        kwargs["domain_id"] = domain_id

        self.db.execute("UPDATE cryptokeys SET active = 1 WHERE domain_id = :domain_id AND id = :id", kwargs)
        self.db.commit()

        self.result = True

    def do_unpublishdomainkey(self, **kwargs):
        try:
            domain_id = self.get_domain_id(kwargs["name"])
        except KeyError:
            return
        kwargs["domain_id"] = domain_id

        self.db.execute("UPDATE cryptokeys SET published = 0 WHERE domain_id = :domain_id AND id = :id", kwargs)
        self.db.commit()

        self.result = True

    def do_publishdomainkey(self, **kwargs):
        try:
            domain_id = self.get_domain_id(kwargs["name"])
        except KeyError:
            return
        kwargs["domain_id"] = domain_id

        self.db.execute("UPDATE cryptokeys SET published = 1 WHERE domain_id = :domain_id AND id = :id", kwargs)
        self.db.commit()

        self.result = True

    def do_getalldomainmetadata(self, name, **kwargs):
        cur = self.db.execute(
            "SELECT kind, content FROM domainmetadata JOIN domains WHERE name = :name", {"name": name}
        )
        self.result = {}
        for row in cur.fetchall():
            if not row[0] in self.result:
                self.result[row[0]] = list()
            self.result[row[0]].append(row[1])

    def do_getdomainmetadata(self, name, kind, **kwargs):
        cur = self.db.execute(
            "SELECT content FROM domainmetadata JOIN domains WHERE name = :name AND kind = :kind",
            {"name": name, "kind": kind},
        )
        self.result = cur.fetchall()

    def do_setdomainmetadata(self, name, kind, value, **kwargs):
        try:
            domain_id = self.get_domain_id(name)
        except KeyError:
            return

        self.db.execute(
            "DELETE FROM domainmetadata WHERE domain_id = :domain_id AND kind = :kind",
            {"domain_id": domain_id, "kind": kind},
        )
        if value:
            self.db.execute(
                "INSERT INTO domainmetadata (domain_id,kind,content) VALUES(:domain_id, :kind, :content)",
                {"domain_id": domain_id, "kind": kind, "content": content},
            )
        self.db.commit()

    def do_starttransaction(self, trxid, **kwargs):
        pass

    def do_committransaction(self, trxid, **kwargs):
        pass

    def do_directbackendcmd(self, query, **kwargs):
        self.result = query
