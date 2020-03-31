BEGIN;
  ALTER TABLE cryptokeys ADD COLUMN published BOOL DEFAULT TRUE;

  ALTER TABLE cryptokeys ADD COLUMN content_new TEXT;
  UPDATE cryptokeys SET content_new = content;
  ALTER TABLE cryptokeys DROP COLUMN content;
  ALTER TABLE cryptokeys RENAME COLUMN content_new TO content;
COMMIT;
