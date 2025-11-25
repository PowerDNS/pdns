import pdns.remotebackend
import time


# define a simple $domain

ID_DOMAIN = {
    1: 'unit.test.',
}

DOMAINS = {
    'unit.test.': {
        'id': 1,
        'ttl': 300,
        'name': 'unit.test.',
        'notified_serial': 0,
        'meta': {},
        'keys': {},
        'rr': {
            'unit.test.' : {
                'SOA': ["ns.unit.test. hostmaster.unit.test. 1 2 3 4 5"],
                'NS':  ["ns1.unit.test.", "ns2.unit.test."],
            },
            'ns1.unit.test.': {
               'A': ["10.0.0.1"]
            },
            'ns2.unit.test.': {
               'A': ["10.0.0.2"]
            },
            'empty.unit.test.': {}
        },
        'kind': 'native',
    },
    'master.test.': {
        'id': 2,
        'ttl': 300,
        'name': 'master.test.',
        'notified_serial': 2,
        'meta': {},
        'keys': {},
        'rr': {
            'master.test.': {
                'SOA': ["ns.master.test. hostmaster.master.test. 1 2 3 4 5"],
            }
        },
        'kind': 'master',
    },
}

TSIG_KEYS = {
    'test.': {
        'name': 'test.',
        'algorithm': 'NULL.',
        'content': 'NULL',
    }
}

MASTERS = {
    'ns1.unit.test.': {
        'ip': '10.0.0.1'
    }
}

class Handler(pdns.remotebackend.Handler):
    def get_domain(self, domain):
        if not domain.endswith("."):
            domain = domain + "."
        while len(domain) > 0:
            if domain in DOMAINS:
                return DOMAINS[domain]
            p = domain.find(".")
            if p == -1:
                break
            domain = domain[p+1:]
        return None

    def do_lookup(self, qname='', qtype='', **kwargs):
        domain = self.get_domain(qname)
        if domain:
            self.result = []
            rrset = domain['rr'].get(qname, {'qtype': []})
            rr = rrset.get(qtype, [])
            for r in rr:
                self.result.append(self.record(qname=qname, qtype=qtype, content=r, ttl=domain['ttl']))

    def do_list(self, zonename="", **kwargs):
        domain = self.get_domain(zonename)
        if domain:
            self.result = []
            for qname, rrset in domain['rr'].items():
                for qtype, rr in rrset.items():
                    for r in rr:
                        self.result.append(self.record(qname=qname, qtype=qtype, content=r, ttl=domain['ttl']))

    def do_getalldomainmetadata(self, name='', **kwargs):
        domain = self.get_domain(name)
        if domain:
            self.result = domain['meta']

    def do_getdomainmetadata(self, name='', kind='', **kwargs):
        self.do_getalldomainmetadata(name=name)
        if self.result:
            self.result = self.result[kind]

    def do_setdomainmetadata(self, name='', kind='', value=None, **kwargs):
        domain = self.get_domain(name)
        if domain:
            if value is None:
                del domain['meta'][kind]
            else:
                domain['meta'][kind] = value
            self.result = True

    def do_adddomainkey(self, name='', key=None, **kwargs):
        if key is None:
            key = {}
        domain = self.get_domain(name)
        if domain:
            k_id = len(domain['keys']) + 1
            key['id'] = k_id
            domain['keys'][k_id] = key
            self.result = k_id

    def do_getdomainkeys(self, name='', **kwargs):
        domain = self.get_domain(name)
        if domain:
            self.result = []
            for k_id, k in domain['keys'].items():
                self.result.append(k)

    def do_activatedomainkey(self, name='', **kwargs):
        domain = self.get_domain(name)
        if domain:
            key = domain['keys'].get(int(kwargs['id']))
            if key:
                key['active'] = True
                self.result = True

    def do_deactivatedomainkey(self, name='', **kwargs):
        domain = self.get_domain(name)
        if domain:
            key = domain['keys'].get(int(kwargs['id']))
            if key:
                key['active'] = False
                self.result = True

    def do_publishdomainkey(self, name='', **kwargs):
        domain = self.get_domain(name)
        if domain:
            key = domain['keys'].get(int(kwargs['id']))
            if key:
                key['published'] = True
                self.result = True

    def do_unpublishdomainkey(self, name='', **kwargs):
        domain = self.get_domain(name)
        if domain:
            key = domain['keys'].get(int(kwargs['id']))
            if key:
                key['published'] = False
                self.result = True

    def do_removedomainkey(self, name='', **kwargs):
        domain = self.get_domain(name)
        if domain:
            k_id = int(kwargs['id'])
            if k_id in domain['keys']:
                del domain['keys'][k_id]
                self.result = True

    def do_getbeforeandafternamesabsolute(self, qname='', **kwargs):
        if qname == 'middle.unit.test.':
            self.result = {
                'unhashed': 'middle.',
                'before': 'begin.',
                'after': 'stop.',
            }

    def do_setnotified(self, **kwargs):
        d_id = int(kwargs['id'])
        domain_name = ID_DOMAIN.get(d_id)
        domain = DOMAINS.get(domain_name)
        if domain:
            domain['notified_serial'] = kwargs['serial']
            self.result = True

    def fill_domaininfo(self, name=""):
        domain = self.get_domain(name)
        if domain:
            self.result.append({
                'id': domain['id'],
                'zone': domain['name'],
                'masters': MASTERS,
                'notified_serial': domain['notified_serial'],
                'serial': domain['notified_serial'],
                'last_check': int(time.time()),
                'kind': domain['kind']
            })

    def do_getdomaininfo(self, name="", **kwargs):
        self.result = []
        self.fill_domaininfo(name)
        if self.result:
            self.result = self.result[0]

    def do_ismaster(self, name='', ip='', **kwargs):
        ips = MASTERS.get(name, [])
        if ip in ips:
            self.result = True

    def do_supermasterbackend(self, domain='', nsset=[], **kwargs):
        d_id = len(DOMAINS) + 1
        dom = domain.lower()
        domainObject = {
            'id': d_id,
            'name': dom,
            'kind': 'slave',
            'notified_serial': 0,
            'meta': {},
            'keys': {},
            'rr': {
                dom: {
                    'SOA': ["ns.%s hostmaster.%s 1 2 3 4 5" % (dom, dom)],
                }
            },
            'ttl': 300,
        }

        nsset = []
        for rr in nsset:
            nsset.append(self.record(qname=rr['qname'], qtype=rr['qtype'], content=rr['content'], ttl=rr['ttl']))

        domainObject['rr'][dom]['NS'] = nsset
        DOMAINS[dom] = domainObject

        self.result = [{
            'nameserver': 'ns.%s' % dom,
            'account': ''
        }]


    def do_createslavedomain(self, domain='', **kwargs):
        d_id = len(DOMAINS) + 1
        dom = domain.lower()
        domainObject = {
            'id': d_id,
            'name': dom,
            'kind': 'slave',
            'notified_serial': 0,
            'ttl': 300,
            'meta': {},
            'keys': {},
            'rr': {
            }
        }
        DOMAINS[dom] = domainObject

        self.result = True

    def do_feedrecord(self, rr={}, **kwargs):
        qname = rr['qname']
        qtype = rr['qtype']
        domain = self.get_domain(qname)
        if domain:
            if not qname in domain['rr']:
                domain['rr'][qname] = {qtype: []}
            elif not qtype in domain['rr'][qname]:
                 domain['rr'][qname][qtype] = []
            domain['rr'][qname][qtype].append(self.record(
                qname=qname,
                qtype=qtype,
                content=rr['content'],
                ttl=rr.get('ttl', domain['ttl']))
            )
            self.result = True

    def do_replacerrset(self, qname='', qtype='', rrset=[], **kwargs):
        domain = self.get_domain(qname)
        if domain and qname in domain['rr']:
            if qtype in domain['rr'][qname]:
                del domain['rr'][qname][qtype]
        for row in rrset:
            self.do_feedrecord(rr=row)

    def do_feedents(self, **kwargs):
        self.result = True

    def do_feedents3(self, **kwargs):
        self.result = True

    def do_gettsigkey(self, name='', **kwargs):
        if name in TSIG_KEYS:
            self.result = TSIG_KEYS[name]

    def do_settsigkey(self, name='', algorithm='', content='', **kwargs):
        TSIG_KEYS[name] = {
            'name': name,
            'algorithm': algorithm,
            'content': content,
        }
        self.result = True

    def do_gettsigkeys(self, **kwargs):
        self.result = []
        for name, key in TSIG_KEYS.items():
            self.result.append(key)

    def do_deletetsigkey(self, name='', **kwargs):
        if name in TSIG_KEYS:
            del TSIG_KEYS[name]
            self.result = True

    def do_starttransaction(self, **kwargs):
        self.result = True

    def do_committransaction(self, **kwargs):
        self.result = True

    def do_aborttransaction(self, **kwargs):
        self.result = True

    def do_directbackendcmd(self, query='', **kwargs):
        self.result = query

    def do_getalldomains(self, **kwargs):
        self.result = []
        for name in DOMAINS.keys():
            self.fill_domaininfo(name=name)

    def do_getupdatedmasters(self, **kwargs):
        self.result = []
        for name in DOMAINS.keys():
            if DOMAINS[name]['kind'] == 'master':
                self.fill_domaininfo(name=name)
