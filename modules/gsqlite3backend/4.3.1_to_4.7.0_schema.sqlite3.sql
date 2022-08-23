.bail on

PRAGMA foreign_keys = 0;

BEGIN TRANSACTION;
  ALTER TABLE domains ADD options VARCHAR(65535) DEFAULT NULL;
  ALTER TABLE domains ADD catalog VARCHAR(255) DEFAULT NULL;

  CREATE INDEX catalog_idx ON domains(catalog);
COMMIT;

PRAGMA foreign_keys = 1;

ANALYZE;
