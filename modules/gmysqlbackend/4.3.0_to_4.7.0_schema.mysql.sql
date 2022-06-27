ALTER TABLE domains ADD options VARCHAR(64000) DEFAULT NULL AFTER notified_serial;
ALTER TABLE domains ADD catalog VARCHAR(255) DEFAULT NULL AFTER options;
ALTER TABLE domains MODIFY type VARCHAR(8) NOT NULL;

CREATE INDEX catalog_idx ON domains(catalog);
