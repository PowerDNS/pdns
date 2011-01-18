alter table records add ordername	VARCHAR(255);
alter table records add auth bool;
create index orderindex on records(ordername);

create table domainmetadata (
 id		SERIAL PRIMARY KEY,
 domain_id	INT REFERENCES domains(id) ON DELETE CASCADE,
 kind		VARCHAR(15),
 content	TEXT
);

create table cryptokeys (
 id		SERIAL PRIMARY KEY,
 domain_id	INT REFERENCES domains(id) ON DELETE CASCADE,
 flags		INT NOT NULL,
 active		BOOL,
 content	TEXT
);		 

GRANT ALL ON domainmetadata TO pdns;
GRANT ALL ON domainmetadata_id_seq TO pdns;
GRANT ALL ON cryptokeys TO pdns;
GRANT ALL ON cryptokeys_id_seq TO pdns;

