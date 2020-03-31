BEGIN TRANSACTION;
  CREATE TABLE cryptokeys_temp (
    id                  INTEGER PRIMARY KEY,
    domain              VARCHAR(255) COLLATE NOCASE,
    flags               INT NOT NULL,
    active              BOOL,
    published           BOOL DEFAULT 1,
    content             TEXT
  );

  INSERT INTO cryptokeys_temp SELECT id,domain,flags,active,1,content FROM cryptokeys;
  DROP TABLE cryptokeys;
  ALTER TABLE cryptokeys_temp RENAME TO cryptokeys;

  CREATE INDEX domainnameindex ON cryptokeys(domain);
COMMIT;
