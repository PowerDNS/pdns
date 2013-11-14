create table domainmetadata (
 id         INT auto_increment,
 domain_id  INT NOT NULL,
 kind       VARCHAR(16),
 content    TEXT,
 primary key(id)
) Engine=InnoDB;

create index domainmetaidindex on domainmetadata(domain_id);


create table tsigkeys (
 id         INT auto_increment,
 name       VARCHAR(255),
 algorithm  VARCHAR(50),
 secret     VARCHAR(255),
 primary key(id)
) Engine=InnoDB;

create unique index namealgoindex on tsigkeys(name, algorithm);
