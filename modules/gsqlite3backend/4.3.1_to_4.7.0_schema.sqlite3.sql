.bail on

PRAGMA foreign_keys = 0;

BEGIN TRANSACTION;
  CREATE TABLE domains_temp (
    id                    INTEGER PRIMARY KEY,
    name                  VARCHAR(255) NOT NULL COLLATE NOCASE,
    master                VARCHAR(128) DEFAULT NULL,
    last_check            INTEGER DEFAULT NULL,
    type                  VARCHAR(8) NOT NULL,
    notified_serial       INTEGER DEFAULT NULL,
    options               VARCHAR(65535) DEFAULT NULL,
    catalog               VARCHAR(255) DEFAULT NULL,
    account               VARCHAR(40) DEFAULT NULL
  );

  INSERT INTO domains_temp SELECT id,name,master,last_check,type,notified_serial,NULL,NULL,account FROM domains;
  DROP TABLE domains;
  ALTER TABLE domains_temp RENAME TO domains;

  CREATE UNIQUE INDEX name_index ON domains(name);
  CREATE INDEX catalog_idx ON domains(catalog);
COMMIT;

PRAGMA foreign_keys = 1;

ANALYZE;
