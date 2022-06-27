BEGIN;
  ALTER TABLE domains ADD COLUMN options VARCHAR(65535) DEFAULT NULL;
  ALTER TABLE domains ADD COLUMN catalog VARCHAR(255) DEFAULT NULL;

  ALTER TABLE domains ADD COLUMN account_new VARCHAR(40) DEFAULT NULL;
  UPDATE domains SET account_new = account;
  ALTER TABLE domains DROP COLUMN account;
  ALTER TABLE domains RENAME COLUMN account_new TO account;

  CREATE INDEX catalog_idx ON domains(catalog);
COMMIT;
