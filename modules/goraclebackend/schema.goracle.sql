CREATE TABLE domains (
  id              INTEGER NOT NULL,
  name            VARCHAR2(255) NOT NULL,
  master          VARCHAR2(128) DEFAULT NULL,
  last_check      INTEGER DEFAULT NULL,
  type            VARCHAR2(6) NOT NULL,
  notified_serial NUMBER(10,0) DEFAULT NULL,
  account         VARCHAR2(40) DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE SEQUENCE domains_id_sequence;
CREATE INDEX domains$name ON domains (name);


CREATE TABLE records (
  id              INTEGER NOT NULL,
  domain_id       INTEGER DEFAULT NULL REFERENCES domains (id) ON DELETE CASCADE,
  name            VARCHAR2(255) DEFAULT NULL,
  type            VARCHAR2(10) DEFAULT NULL,
  content         VARCHAR2(4000) DEFAULT NULL,
  ttl             INTEGER DEFAULT NULL,
  prio            INTEGER DEFAULT NULL,
  disabled        NUMBER(1,0) DEFAULT 0 NOT NULL,
  ordername       VARCHAR2(255) DEFAULT NULL,
  auth            NUMBER(1,0) DEFAULT 1 NOT NULL,
  PRIMARY KEY (id)
) pctfree 40;

CREATE SEQUENCE records_id_sequence;
CREATE INDEX records$nametype ON records (name, type);
CREATE INDEX records$domain_id ON records (domain_id);
CREATE INDEX records$recordorder ON records (domain_id, ordername);


CREATE TABLE supermasters (
  ip              VARCHAR2(64) NOT NULL,
  nameserver      VARCHAR2(255) NOT NULL,
  account         VARCHAR2(40) NOT NULL,
  PRIMARY KEY (ip, nameserver)
);


CREATE TABLE comments (
  id              INTEGER NOT NULL,
  domain_id       INTEGER NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
  name            VARCHAR2(255) NOT NULL,
  type            VARCHAR2(10) NOT NULL,
  modified_at     INTEGER NOT NULL,
  account         VARCHAR2(40) NOT NULL,
  "comment"       VARCHAR2(4000) NOT NULL
);
CREATE SEQUENCE comments_id_sequence;
CREATE INDEX comments$nametype ON comments (name, type);
CREATE INDEX comments$domain_id ON comments (domain_id);
CREATE INDEX comments$order ON comments (domain_id, modified_at);


CREATE TABLE domainmetadata (
  id              INTEGER NOT NULL,
  domain_id       INTEGER NOT NULL,
  kind            VARCHAR2(32),
  content         VARCHAR2(4000),
  PRIMARY KEY (id)
);

CREATE SEQUENCE domainmetadata_id_sequence;
CREATE INDEX domainmetadata$domain_id ON domainmetadata (domain_id);


CREATE TABLE cryptokeys (
  id              INTEGER NOT NULL,
  domain_id       INTEGER NOT NULL,
  flags           INTEGER NOT NULL,
  active          INTEGER NOT NULL,
  content         VARCHAR2(4000),
  PRIMARY KEY (id)
);

CREATE SEQUENCE cryptokeys_id_sequence;
CREATE INDEX cryptokeys$domain_id ON cryptokeys (domain_id);


CREATE TABLE tsigkeys (
  id              INTEGER NOT NULL,
  name            VARCHAR2(255),
  algorithm       VARCHAR2(50),
  secret          VARCHAR2(255),
  PRIMARY KEY (id)
);

CREATE SEQUENCE tsigkeys_id_sequence;
CREATE UNIQUE INDEX tsigkeys$namealgo ON tsigkeys (name, algorithm);
