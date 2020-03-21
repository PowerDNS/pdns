BEGIN TRANSACTION;
  CREATE TABLE cryptokeys_temp (
    id                  INTEGER PRIMARY KEY,
    domain_id           INT NOT NULL,
    flags               INT NOT NULL,
    active              BOOL,
    published           BOOL DEFAULT 1,
    content             TEXT,
    FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE
  );

  INSERT INTO cryptokeys_temp SELECT id,domain_id,flags,active,published,content FROM cryptokeys;
  DROP TABLE cryptokeys;
  ALTER TABLE cryptokeys_temp RENAME TO cryptokeys;

  CREATE INDEX domainidindex ON cryptokeys(domain_id);
COMMIT;
