alter table records add ordername	VARCHAR(255);
alter table records add auth bool;
create index orderindex on records(ordername);

create table domainmetadata (
 id		SERIAL PRIMARY KEY,
 domain_id	INT REFERENCES domains(id) ON DELETE CASCADE,
 kind		VARCHAR(16),
 content	TEXT
);

create index domainidmetaindex on domainmetadata(domain_id);               


create table cryptokeys (
 id		SERIAL PRIMARY KEY,
 domain_id	INT REFERENCES domains(id) ON DELETE CASCADE,
 flags		INT NOT NULL,
 active		BOOL,
 content	TEXT
);		 
create index domainidindex on cryptokeys(domain_id);


GRANT ALL ON domainmetadata TO pdns;
GRANT ALL ON domainmetadata_id_seq TO pdns;
GRANT ALL ON cryptokeys TO pdns;
GRANT ALL ON cryptokeys_id_seq TO pdns;

create table tsigkeys (
 id		SERIAL PRIMARY KEY,
 name		VARCHAR(255),
 algorithm	VARCHAR(255), 
 secret		VARCHAR(255)
);

create unique index namealgoindex on tsigkeys(name, algorithm);

GRANT ALL ON tsigkeys TO pdns;
GRANT ALL ON tsigkeys_id_seq TO pdns;
alter table records alter column type type VARCHAR(10);
