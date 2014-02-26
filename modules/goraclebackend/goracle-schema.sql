create table domains (
  id              NUMBER,
  name            VARCHAR(255) NOT NULL,
  master          VARCHAR(128) DEFAULT NULL,
  last_check      INT DEFAULT NULL,
  type            VARCHAR(6) NOT NULL,
  notified_serial INT DEFAULT NULL,
  account         VARCHAR(40) DEFAULT NULL,
  primary key (id)
);

create sequence DOMAINS_ID_SEQUENCE;
create index DOMAINS$NAME on domains (NAME);


CREATE TABLE records (
  id              number(11) not NULL,
  domain_id       INT DEFAULT NULL REFERENCES Domains(ID) ON DELETE CASCADE,
  name            VARCHAR(255) DEFAULT NULL,
  type            VARCHAR(10) DEFAULT NULL,
  content         VARCHAR2(4000) DEFAULT NULL,
  ttl             INT DEFAULT NULL,
  prio            INT DEFAULT NULL,
  change_date     INT DEFAULT NULL,
  disabled        INT DEFAULT 0,
  ordername       VARCHAR(255) DEFAULT NULL,
  auth            INT DEFAULT NULL,
  primary key (id)
) pctfree 40;

create index records$nametype on records (name, type);
create index records$domain_id on records (domain_id);
create index records$recordorder on records (domain_id, ordername);
create sequence records_id_sequence;


create table supermasters (
  ip              VARCHAR(64) NOT NULL,
  nameserver      VARCHAR(255) NOT NULL,
  account         VARCHAR(40) DEFAULT NULL,
  PRIMARY KEY(ip, nameserver)
);


CREATE TABLE comments (
  id              number(11) not NULL,
  domain_id       INT NOT NULL REFERENCES Domains(ID) ON DELETE CASCADE,
  name            VARCHAR(255) NOT NULL,
  type            VARCHAR(10) NOT NULL,
  modified_at     INT NOT NULL,
  account         VARCHAR(40) NOT NULL,
  comment         VARCHAR2(4000) NOT NULL
);
CREATE INDEX comments$nametype ON comments (name, type);
CREATE INDEX comments$domain_id ON comments (domain_id);
CREATE INDEX comments$order ON comments (domain_id, modified_at);
CREATE SEQUENCE comments_id_sequence;


create table domainmetadata (
  id              NUMBER,
  domain_id       INT NOT NULL,
  kind            VARCHAR(16),
  content         VARCHAR2(4000),
  primary key(id)
);

create sequence DOMAINMETADATA_ID_SEQUENCE;
create index domainmetadata$domainid on domainmetadata(domain_id);


create table cryptokeys (
  id              NUMBER,
  domain_id       INT NOT NULL,
  flags           INT NOT NULL,
  active          INT NOT NULL,
  content         VARCHAR2(4000),
  primary key(id)
);

create sequence CRYPTOKEYS_ID_SEQUENCE;
create index cryptokeys$domainid on cryptokeys(domain_id);


create table tsigkeys (
  id              NUMBER,
  name            VARCHAR(255),
  algorithm       VARCHAR(50),
  secret          VARCHAR(255),
  primary key(id)
);

create sequence TSIGKEYS_ID_SEQUENCE;
create unique index tsigkeys$namealgo on tsigkeys(name, algorithm);
