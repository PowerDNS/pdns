ALTER TABLE records ADD disabled BOOL DEFAULT 0;
ALTER TABLE records ADD ordername VARCHAR(255);
ALTER TABLE records ADD auth BOOL DEFAULT 1;

CREATE INDEX orderindex ON records(ordername);


CREATE TABLE domainmetadata (
  id                    INTEGER PRIMARY KEY,
  domain_id             INT NOT NULL,
  kind                  VARCHAR(32) COLLATE NOCASE,
  content               TEXT
);

CREATE INDEX domainmetaidindex on domainmetadata(domain_id);


CREATE TABLE cryptokeys (
  id                    INTEGER PRIMARY KEY,
  domain_id             INT NOT NULL,
  flags                 INT NOT NULL,
  active                BOOL,
  content               TEXT
);

CREATE INDEX domainidindex ON cryptokeys(domain_id);


CREATE TABLE tsigkeys (
  id                    INTEGER PRIMARY KEY,
  name                  VARCHAR(255) COLLATE NOCASE,
  algorithm             VARCHAR(50) COLLATE NOCASE,
  secret                VARCHAR(255)
);

CREATE UNIQUE INDEX namealgoindex ON tsigkeys(name, algorithm);


CREATE TABLE comments (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               VARCHAR(65535) NOT NULL
);

CREATE INDEX comments_domain_id_index ON comments (domain_id);
CREATE INDEX comments_nametype_index ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);


BEGIN TRANSACTION;
  CREATE TEMPORARY TABLE supermasters_backup (
    ip                  VARCHAR(64) NOT NULL,
    nameserver          VARCHAR(255) NOT NULL COLLATE NOCASE,
    account             VARCHAR(40) DEFAULT NULL
  );

  INSERT INTO supermasters_backup SELECT ip, nameserver, account FROM supermasters;
  UPDATE supermasters_backup SET account='' WHERE account IS NULL;
  DROP TABLE supermasters;

  CREATE TABLE supermasters (
    ip                  VARCHAR(64) NOT NULL,
    nameserver          VARCHAR(255) NOT NULL COLLATE NOCASE,
    account             VARCHAR(40) NOT NULL
  );
  CREATE UNIQUE INDEX ip_nameserver_pk ON supermasters(ip, nameserver);

  INSERT INTO supermasters SELECT ip, nameserver, account FROM supermasters_backup;
  DROP TABLE supermasters_backup;
COMMIT;
