CREATE TABLE domains (
  id                    INT IDENTITY,
  name                  VARCHAR(255) NOT NULL,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INT DEFAULT NULL,
  type                  VARCHAR(6) NOT NULL,
  notified_serial       INT DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE UNIQUE INDEX name_index ON domains(name);

CREATE TABLE records (
  id                    INT IDENTITY,
  domain_id             INT DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(MAX) DEFAULT NULL,
  ttl                   INT DEFAULT NULL,
  prio                  INT DEFAULT NULL,
  disabled              BIT DEFAULT 0,
  ordername             VARBINARY(255) DEFAULT NULL,
  auth                  BIT DEFAULT 1,
  PRIMARY KEY (id)
);

CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);
CREATE INDEX recordorder ON records (domain_id, ordername);


CREATE TABLE supermasters (
  ip                    VARCHAR(64) NOT NULL,
  nameserver            VARCHAR(255) NOT NULL,
  account               VARCHAR(40) NOT NULL,
  PRIMARY KEY (ip, nameserver)
);


CREATE TABLE comments (
  id                    INT IDENTITY,
  domain_id             INT NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) NOT NULL,
  comment               VARCHAR(MAX) NOT NULL,
  PRIMARY KEY (id)
);

CREATE INDEX comments_domain_id_idx ON comments (domain_id);
CREATE INDEX comments_name_type_idx ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);


CREATE TABLE domainmetadata (
  id                    INT IDENTITY,
  domain_id             INT NOT NULL,
  kind                  VARCHAR(32),
  content               VARCHAR(MAX),
  PRIMARY KEY (id)
);

CREATE INDEX domainmetadata_idx ON domainmetadata (domain_id, kind);

CREATE TABLE cryptokeys (
  id                    INT IDENTITY,
  domain_id             INT NOT NULL,
  flags                 INT NOT NULL,
  active                BIT,
  content               VARCHAR(MAX),
  PRIMARY KEY(id)
);

CREATE INDEX domainidindex ON cryptokeys(domain_id);


CREATE TABLE tsigkeys (
  id                    INT IDENTITY,
  name                  VARCHAR(255),
  algorithm             VARCHAR(50),
  secret                VARCHAR(255),
  PRIMARY KEY (id)
);

CREATE UNIQUE INDEX namealgoindex ON tsigkeys(name, algorithm);
