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
  CREATE TEMPORARY TABLE records_backup(
    id                  INTEGER PRIMARY KEY,
    domain_id           INTEGER DEFAULT NULL,
    name                VARCHAR(255) DEFAULT NULL,
    type                VARCHAR(10) DEFAULT NULL,
    content             VARCHAR(65535) DEFAULT NULL,
    ttl                 INTEGER DEFAULT NULL,
    prio                INTEGER DEFAULT NULL,
    change_date         INTEGER DEFAULT NULL,
    ordername           VARCHAR(255),
    auth                BOOL DEFAULT 1
  );

  INSERT INTO records_backup SELECT id,domain_id,name,type,content,ttl,prio,change_date,ordername,auth FROM records;
  DROP TABLE records;

  CREATE TABLE records (
    id                  INTEGER PRIMARY KEY,
    domain_id           INTEGER DEFAULT NULL,
    name                VARCHAR(255) DEFAULT NULL,
    type                VARCHAR(10) DEFAULT NULL,
    content             VARCHAR(65535) DEFAULT NULL,
    ttl                 INTEGER DEFAULT NULL,
    prio                INTEGER DEFAULT NULL,
    change_date         INTEGER DEFAULT NULL,
    disabled            BOOLEAN DEFAULT 0,
    ordername           VARCHAR(255),
    auth                BOOL DEFAULT 1
  );

  CREATE INDEX rec_name_index ON records(name);
  CREATE INDEX nametype_index ON records(name,type);
  CREATE INDEX domain_id ON records(domain_id);
  CREATE INDEX orderindex ON records(ordername);

  INSERT INTO records SELECT id,domain_id,name,type,content,ttl,prio,change_date,0,ordername,auth FROM records_backup;
  DROP TABLE records_backup;
COMMIT;


BEGIN TRANSACTION;
  CREATE TEMPORARY TABLE supermasters_backup (
    ip                  VARCHAR(64) NOT NULL,
    nameserver          VARCHAR(255) NOT NULL COLLATE NOCASE,
    account             VARCHAR(40) DEFAULT NULL
  );

  INSERT INTO supermasters_backup SELECT ip,nameserver,account FROM supermasters;
  UPDATE supermasters_backup SET account='' WHERE account IS NULL;
  DROP TABLE supermasters;

  CREATE TABLE supermasters (
    ip                  VARCHAR(64) NOT NULL,
    nameserver          VARCHAR(255) NOT NULL COLLATE NOCASE,
    account             VARCHAR(40) NOT NULL
  );
  CREATE UNIQUE INDEX ip_nameserver_pk ON supermasters(ip, nameserver);

  INSERT INTO supermasters SELECT ip,nameserver,account FROM supermasters_backup;
  DROP TABLE supermasters_backup;
COMMIT;


BEGIN TRANSACTION;
  CREATE TABLE domainmetadata_backup (
    id INTEGER PRIMARY KEY,
    domain_id INT NOT NULL,
    kind VARCHAR(32) COLLATE NOCASE,
    content TEXT
  );

  INSERT INTO domainmetadata_backup SELECT id,domain_id,kind,content FROM domainmetadata;
  DROP TABLE domainmetadata;

  CREATE TABLE domainmetadata (
    id INTEGER PRIMARY KEY,
    domain_id INT NOT NULL,
    kind VARCHAR(32) COLLATE NOCASE,
    content TEXT
  );
  CREATE INDEX domainmetaidindex ON domainmetadata(domain_id);

  INSERT INTO domainmetadata SELECT id,domain_id,kind,content FROM domainmetadata_backup;
  DROP TABLE domainmetadata_backup;
COMMIT;
