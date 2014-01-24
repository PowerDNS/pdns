alter table records add ordername      VARCHAR(255);
alter table records add auth bool;
create index orderindex on records(ordername);

create table domainmetadata (
 id        INTEGER PRIMARY KEY,
 domain_id INT NOT NULL,
 kind      VARCHAR(16) COLLATE NOCASE,
 content   TEXT
);

create index domainmetaidindex on domainmetadata(domain_id);

create table cryptokeys (
 id        INTEGER PRIMARY KEY,
 domain_id INT NOT NULL,
 flags     INT NOT NULL,
 active    BOOL,
 content   TEXT
);

create index domainidindex on cryptokeys(domain_id);

create table tsigkeys (
 id        INTEGER PRIMARY KEY,
 name      VARCHAR(255) COLLATE NOCASE,
 algorithm VARCHAR(50) COLLATE NOCASE,
 secret    VARCHAR(255)
);

create unique index namealgoindex on tsigkeys(name, algorithm);
