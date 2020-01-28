create table domainmetadata (
 id         INTEGER PRIMARY KEY,
 domain     VARCHAR(255) COLLATE NOCASE,
 kind       VARCHAR(32) COLLATE NOCASE,
 content    TEXT
);

create index domainmetanameindex on domainmetadata(domain);

create table cryptokeys (
 id         INTEGER PRIMARY KEY,
 domain     VARCHAR(255) COLLATE NOCASE,
 flags      INT NOT NULL,
 active     BOOL,
 published  BOOL,
 content    TEXT
);

create index domainnameindex on cryptokeys(domain);

create table tsigkeys (
 id         INTEGER PRIMARY KEY,
 name       VARCHAR(255) COLLATE NOCASE,
 algorithm  VARCHAR(50) COLLATE NOCASE,
 secret     VARCHAR(255)
);

create unique index namealgoindex on tsigkeys(name, algorithm);
