ALTER TABLE domains ALTER COLUMN type TYPE text;
ALTER TABLE domains ADD COLUMN options TEXT DEFAULT NULL,
  ADD COLUMN catalog TEXT DEFAULT NULL;

CREATE INDEX catalog_idx ON domains(catalog);
