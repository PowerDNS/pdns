CREATE TABLE dns (
    domain      text PRIMARY KEY,
    records     list<frozen<tuple<ascii, text, int, text, text>>>,
    keys        list<frozen<tuple<boolean, int, text, int>>>,
    metadata    map<ascii, text>
);

INSERT INTO dns (domain, records) VALUES
(
    'ngjit.net',
    [
        ('A',   '',     3600, '1.1.1.1'),
        ('NS',  '',     3600, 'ns1.ngjit.net'),
        ('NS',  '',     3600, 'ns2.ngjit.net'),
        ('SOA', '',     3600, 'ns1.ngjit.net. support.ddos-guard.net. 0 10800 3600 604800 3600'),
        ('A',   'ns1',  3600, '1.1.1.1'),
        ('A',   'ns2',  3600, '1.1.1.1')
    ]
);

INSERT INTO dns (domain, records) VALUES
(
    'ngjit.ru',
    [
        ('MX',  '',    3600, '10 mx1.ngjit.ru'),
        ('MX',  '',    3600, '20 mx2.ngjit.ru'),
        ('NS',  '',     3600, 'ns1.ngjit.ru'),
        ('NS',  '',     3600, 'ns2.ngjit.ru'),
        ('A',   'ns2',  3600, '1.1.1.1'),
        ('A',   'ns1',  3600, '1.1.1.1'),
        ('A',   'mx1',  3600, '2.2.2.2'),
        ('A',   'mx2',  3600, '3.3.3.3'),
        ('SOA', '',     3600, 'ns1.ngjit.net. support.ddos-guard.net. 0 10800 3600 604800 3600')
    ]
);
