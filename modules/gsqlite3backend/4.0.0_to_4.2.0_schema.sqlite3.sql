BEGIN TRANSACTION;
    CREATE TEMPORARY TABLE records_backup (
      id                    INTEGER PRIMARY KEY,
      domain_id             INTEGER DEFAULT NULL,
      name                  VARCHAR(255) DEFAULT NULL,
      type                  VARCHAR(10) DEFAULT NULL,
      content               VARCHAR(65535) DEFAULT NULL,
      ttl                   INTEGER DEFAULT NULL,
      prio                  INTEGER DEFAULT NULL,
      disabled              BOOLEAN DEFAULT 0,
      ordername             VARCHAR(255),
      auth                  BOOL DEFAULT 1
    );

    INSERT INTO records_backup SELECT id,domain_id,name,type,content,ttl,prio,disabled,ordername,auth FROM records;
    DROP TABLE records;

    CREATE TABLE records (
      id                    INTEGER PRIMARY KEY,
      domain_id             INTEGER DEFAULT NULL,
      name                  VARCHAR(255) DEFAULT NULL,
      type                  VARCHAR(10) DEFAULT NULL,
      content               VARCHAR(65535) DEFAULT NULL,
      ttl                   INTEGER DEFAULT NULL,
      prio                  INTEGER DEFAULT NULL,
      disabled              BOOLEAN DEFAULT 0,
      ordername             VARCHAR(255),
      auth                  BOOL DEFAULT 1,
      FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
    );

    CREATE INDEX rec_name_index ON records(name);
    CREATE INDEX nametype_index ON records(name,type);
    CREATE INDEX domain_id ON records(domain_id);
    CREATE INDEX orderindex ON records(ordername);

    INSERT INTO records SELECT id,domain_id,name,type,content,ttl,prio,disabled,ordername,auth FROM records_backup;
    DROP TABLE records_backup;
COMMIT;
