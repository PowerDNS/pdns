create table domainmetadata (
 id		 INT auto_increment,
 domain_id       INT NOT NULL,
 kind		 VARCHAR(16),
 content	TEXT,
 primary key(id)
);

create index domainmetaidindex on domainmetadata(domain_id);               


create table cryptokeys (
 id		INT auto_increment,
 domain_id      INT NOT NULL,
 flags		INT NOT NULL,
 active		BOOL,
 content	TEXT,
 primary key(id)
);		 

create index domainidindex on cryptokeys(domain_id);           

alter table records add ordername      VARCHAR(255) BINARY;
alter table records add auth bool;
create index recordorder on records (domain_id, ordername);

create table tsigkeys (
 id		INT auto_increment,
 name		VARCHAR(255), 
 algorithm	VARCHAR(50),
 secret		VARCHAR(255),
 primary key(id)
);

create unique index namealgoindex on tsigkeys(name, algorithm);
alter table records change column type type VARCHAR(10);
