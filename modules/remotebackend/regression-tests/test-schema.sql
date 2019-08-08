begin transaction;

create table domains (
  id                INTEGER PRIMARY KEY,
  name              VARCHAR(255) NOT NULL COLLATE NOCASE,
  master            VARCHAR(128) DEFAULT NULL,
  last_check        INTEGER DEFAULT NULL,
  type              VARCHAR(6) NOT NULL,
  notified_serial   INTEGER DEFAULT NULL, 
  account           VARCHAR(40) DEFAULT NULL
);

CREATE UNIQUE INDEX name_index ON domains(name);

CREATE TABLE records (
  id              INTEGER PRIMARY KEY,
  domain_id       INTEGER DEFAULT NULL,
  name            VARCHAR(255) DEFAULT NULL, 
  type            VARCHAR(10) DEFAULT NULL,
  content         VARCHAR(65535) DEFAULT NULL,
  ttl             INTEGER DEFAULT NULL,
  prio            INTEGER DEFAULT NULL,
  ordername       VARCHAR(255) DEFAULT NULL,
  auth            BOOL DEFAULT 0
);
              
CREATE INDEX rec_name_index ON records(name);
CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);
create index orderindex on records(ordername);

create table supermasters (
  ip          VARCHAR(25) NOT NULL, 
  nameserver  VARCHAR(255) NOT NULL COLLATE NOCASE, 
  account     VARCHAR(40) DEFAULT NULL
);

create table domainmetadata (
 id         INTEGER PRIMARY KEY,
 domain_id       INT NOT NULL,
 kind         VARCHAR(16) COLLATE NOCASE,
 content    TEXT
);

create index domainmetaidindex on domainmetadata(domain_id);

create table cryptokeys (
 id        INTEGER PRIMARY KEY,
 domain_id      INT NOT NULL,
 flags        INT NOT NULL,
 active        BOOL,
 content    TEXT
);         

create index domainidindex on cryptokeys(domain_id);           

create table tsigkeys (
 id        INTEGER PRIMARY KEY,
 name        VARCHAR(255) COLLATE NOCASE,
 algorithm    VARCHAR(50) COLLATE NOCASE,
 secret        VARCHAR(255)
);

create unique index namealgoindex on tsigkeys(name, algorithm);

insert into domains (name,type) VALUES('example.com.','NATIVE');
insert into domains (name,type) VALUES('up.example.com.','NATIVE');

insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "example.com.", "SOA", "120", "ns1.example.com. hostmaster.example.com. 2000010101 28800 7200 1209600 120", "", 1 FROM domains WHERE name = "example.com."; 
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "example.com.", "NS", "120", "ns1.example.com.", "", 1 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "example.com.", "NS", "120", "ns2.example.com.", "", 1 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "outpost.example.com.", "A", "120", "192.168.2.1", "outpost", 1 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "outpost.example.com.", "AAAA", "120", "fe80::1", "outpost", 1 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "www.example.com.", "A", "120", "192.168.2.255", "www", 1 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "up.example.com.", "NS", "120", "ns1.example.com.", "up", 0 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "up.example.com.", "NS", "120", "ns2.example.com.", "up", 0 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "ns1.example.com.", "A", "120", "192.168.2.2", "ns1", 1 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "ns2.example.com.", "A", "120", "192.168.2.3", "ns2", 1 FROM domains WHERE name = "example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "up.example.com.", "SOA", "120", "ns1.example.com. hostmaster.example.com. 2000010101 28800 7200 1209600 120", "", 1 FROM domains WHERE name = "up.example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "up.example.com.", "NS", "120", "ns1.example.com.", "", 1 FROM domains WHERE name = "up.example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "up.example.com.", "NS", "120", "ns2.example.com.", "", 1 FROM domains WHERE name = "up.example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "jump.up.example.com.", "A", "120", "192.168.3.1", "jump", 1 FROM domains WHERE name = "up.example.com.";
insert into records (domain_id, name, type, ttl, content, ordername, auth) select id as domain_id, "jump.up.example.com.", "TXT", "120", "a very very long indeed text string that should pass out clean and proper thru the entire chain of powerdns processing", "jump", 1 FROM domains WHERE name = "up.example.com.";

commit;
