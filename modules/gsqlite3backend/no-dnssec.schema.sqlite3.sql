create table domains (
  id                INTEGER PRIMARY KEY,
  name              VARCHAR(255) NOT NULL COLLATE NOCASE,
  master            VARCHAR(128) DEFAULT NULL,
  last_check        INTEGER DEFAULT NULL,
  type              VARCHAR(6) NOT NULL,
  notified_serial   INTEGER DEFAULT NULL,
  account           VARCHAR(40) DEFAULT NULL
);

CREATE UNIQUE INDEX name_index ON domains(name);

CREATE TABLE records (
  id              INTEGER PRIMARY KEY,
  domain_id       INTEGER DEFAULT NULL,
  name            VARCHAR(255) DEFAULT NULL,
  type            VARCHAR(10) DEFAULT NULL,
  content         VARCHAR(65535) DEFAULT NULL,
  ttl             INTEGER DEFAULT NULL,
  prio            INTEGER DEFAULT NULL,
  change_date     INTEGER DEFAULT NULL,
  disabled        BOOLEAN DEFAULT 0
);

CREATE INDEX rec_name_index ON records(name);
CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);

create table supermasters (
  ip          VARCHAR(64) NOT NULL,
  nameserver  VARCHAR(255) NOT NULL COLLATE NOCASE,
  account     VARCHAR(40) DEFAULT NULL
);

CREATE UNIQUE INDEX ip_nameserver_pk ON supermasters(ip, nameserver);

CREATE TABLE comments (
  id              INTEGER PRIMARY KEY,
  domain_id       INTEGER NOT NULL,
  name            VARCHAR(255) NOT NULL,
  type            VARCHAR(10) NOT NULL,
  modified_at     INT NOT NULL,
  account         VARCHAR(40) DEFAULT NULL,
  comment         VARCHAR(65535) NOT NULL
);
CREATE INDEX comments_domain_id_index ON comments (domain_id);
CREATE INDEX comments_nametype_index ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);
