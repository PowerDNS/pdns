-- Disable foreign keys, if any
PRAGMA foreign_keys = 0;

-- Replace records-table
BEGIN TRANSACTION;
    CREATE TEMPORARY TABLE records_backup (
      id                    INTEGER PRIMARY KEY,
      domain_id             INTEGER DEFAULT NULL,
      name                  VARCHAR(255) DEFAULT NULL,
      type                  VARCHAR(10) DEFAULT NULL,
      content               VARCHAR(65535) DEFAULT NULL,
      ttl                   INTEGER DEFAULT NULL,
      prio                  INTEGER DEFAULT NULL,
      change_date           INTEGER DEFAULT NULL,
      disabled              BOOLEAN DEFAULT 0,
      ordername             VARCHAR(255),
      auth                  BOOL DEFAULT 1
    );

    INSERT INTO records_backup SELECT id,domain_id,name,type,content,ttl,prio,change_date,disabled,ordername,auth FROM records;
    DROP TABLE records;

    CREATE TABLE records (
      id                    INTEGER PRIMARY KEY,
      domain_id             INTEGER DEFAULT NULL,
      name                  VARCHAR(255) DEFAULT NULL,
      type                  VARCHAR(10) DEFAULT NULL,
      content               VARCHAR(65535) DEFAULT NULL,
      ttl                   INTEGER DEFAULT NULL,
      prio                  INTEGER DEFAULT NULL,
      change_date           INTEGER DEFAULT NULL,
      disabled              BOOLEAN DEFAULT 0,
      ordername             VARCHAR(255),
      auth                  BOOL DEFAULT 1,
      FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
    );

    CREATE INDEX rec_name_index ON records(name);
    CREATE INDEX nametype_index ON records(name,type);
    CREATE INDEX domain_id ON records(domain_id);
    CREATE INDEX orderindex ON records(ordername);

    INSERT INTO records SELECT id,domain_id,name,type,content,ttl,prio,change_date,disabled,ordername,auth FROM records_backup;
    DROP TABLE records_backup;
COMMIT;

-- Replace comments-table
BEGIN TRANSACTION;
    CREATE TEMPORARY TABLE comments_backup (
      id                    INTEGER PRIMARY KEY,
      domain_id             INTEGER NOT NULL,
      name                  VARCHAR(255) NOT NULL,
      type                  VARCHAR(10) NOT NULL,
      modified_at           INT NOT NULL,
      account               VARCHAR(40) DEFAULT NULL,
      comment               VARCHAR(65535) NOT NULL
    );

    INSERT INTO comments_backup SELECT id,domain_id,name,type,modified_at,account,comment FROM comments;
    DROP TABLE comments;

    CREATE TABLE comments (
      id                    INTEGER PRIMARY KEY,
      domain_id             INTEGER NOT NULL,
      name                  VARCHAR(255) NOT NULL,
      type                  VARCHAR(10) NOT NULL,
      modified_at           INT NOT NULL,
      account               VARCHAR(40) DEFAULT NULL,
      comment               VARCHAR(65535) NOT NULL,
      FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
    );

    CREATE INDEX comments_domain_id_index ON comments (domain_id);
    CREATE INDEX comments_nametype_index ON comments (name, type);
    CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);

    INSERT INTO comments SELECT id,domain_id,name,type,modified_at,account,comment FROM comments_backup;
    DROP TABLE comments_backup;
COMMIT;

-- Replace domainmetadata-table
BEGIN TRANSACTION;
    CREATE TEMPORARY TABLE domainmetadata_backup (
     id                     INTEGER PRIMARY KEY,
     domain_id              INT NOT NULL,
     kind                   VARCHAR(32) COLLATE NOCASE,
     content                TEXT
    );

    INSERT INTO domainmetadata_backup SELECT id,domain_id,kind,content FROM domainmetadata;
    DROP TABLE domainmetadata;

    CREATE TABLE domainmetadata (
     id                     INTEGER PRIMARY KEY,
     domain_id              INT NOT NULL,
     kind                   VARCHAR(32) COLLATE NOCASE,
     content                TEXT,
     FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
    );

    CREATE INDEX domainmetaidindex ON domainmetadata(domain_id);

    INSERT INTO domainmetadata SELECT id,domain_id,kind,content FROM domainmetadata_backup;
    DROP TABLE domainmetadata_backup;
COMMIT;

-- Replace cryptokeys-table
BEGIN TRANSACTION;
    CREATE TEMPORARY TABLE cryptokeys_backup (
     id                     INTEGER PRIMARY KEY,
     domain_id              INT NOT NULL,
     flags                  INT NOT NULL,
     active                 BOOL,
     content                TEXT
    );

    INSERT INTO cryptokeys_backup SELECT id,domain_id,flags,active,content FROM cryptokeys;
    DROP TABLE cryptokeys;

    CREATE TABLE cryptokeys (
     id                     INTEGER PRIMARY KEY,
     domain_id              INT NOT NULL,
     flags                  INT NOT NULL,
     active                 BOOL,
     content                TEXT,
     FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
    );

    CREATE INDEX domainidindex ON cryptokeys(domain_id);
    INSERT INTO cryptokeys SELECT id,domain_id,flags,active,content FROM cryptokeys_backup;
    DROP TABLE cryptokeys_backup;
COMMIT;

-- Check the current database for FOREIGN_KEYS after enabling it again
PRAGMA foreign_keys = 1;

-- This command checks the status of the constraints. Output is in the form of:
-- [table]|[id]|[referred table]|[id])(which is probably 0, since the constraint fails)]
PRAGMA foreign_key_check;
