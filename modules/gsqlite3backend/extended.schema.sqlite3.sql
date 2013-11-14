create table domainmetadata (
 id        INTEGER PRIMARY KEY,
 domain_id INT NOT NULL,
 kind      VARCHAR(16) COLLATE NOCASE,
 content   TEXT
);

create index domainmetaidindex on domainmetadata(domain_id);


create table tsigkeys (
 id        INTEGER PRIMARY KEY,
 name      VARCHAR(255) COLLATE NOCASE,
 algorithm VARCHAR(50) COLLATE NOCASE,
 secret    VARCHAR(255)
);

create unique index namealgoindex on tsigkeys(name, algorithm);
