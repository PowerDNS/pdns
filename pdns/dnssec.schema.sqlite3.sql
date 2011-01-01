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

