alter table records add ordername      VARCHAR(255);
alter table records add auth bool;
create index orderindex on records(ordername);

create table domainmetadata (
 id		 INTEGER PRIMARY KEY,
 domain_id       INT NOT NULL,
 kind		 VARCHAR(15),
 content	TEXT
);

create table cryptokeys (
 id		INTEGER PRIMARY KEY,
 domain_id      INT DEFAULT NULL,
 flags		INT NOT NULL,
 active		BOOL,
 content	TEXT
);		 

