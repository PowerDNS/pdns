/* Uncomment next line for versions <= 3.3 */
/* ALTER TABLE domains ADD CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT))); */

ALTER TABLE records ADD disabled BOOL DEFAULT 'f';
ALTER TABLE records ALTER COLUMN content TYPE VARCHAR(65535);
ALTER TABLE records ADD ordername VARCHAR(255);
ALTER TABLE records ADD auth BOOL DEFAULT 't';
ALTER TABLE records ALTER COLUMN type TYPE VARCHAR(10);
ALTER TABLE supermasters ALTER COLUMN ip TYPE INET USING ip::INET;
ALTER TABLE supermasters ALTER COLUMN account SET DEFAULT NOT NULL;
ALTER TABLE supermasters ADD CONSTRAINT supermasters_pkey PRIMARY KEY (ip, nameserver);

CREATE INDEX recordorder ON records (domain_id, ordername text_pattern_ops);


CREATE TABLE domainmetadata (
 id                     SERIAL PRIMARY KEY,
 domain_id              INT REFERENCES domains(id) ON DELETE CASCADE,
 kind                   VARCHAR(32),
 content                TEXT
);

CREATE INDEX domainidmetaindex ON domainmetadata(domain_id);


CREATE TABLE cryptokeys (
 id                     SERIAL PRIMARY KEY,
 domain_id              INT REFERENCES domains(id) ON DELETE CASCADE,
 flags                  INT NOT NULL,
 active                 BOOL,
 content                TEXT
);

CREATE INDEX domainidindex ON cryptokeys(domain_id);


CREATE TABLE tsigkeys (
 id                     SERIAL PRIMARY KEY,
 name                   VARCHAR(255),
 algorithm              VARCHAR(50),
 secret                 VARCHAR(255),
 constraint c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);

CREATE UNIQUE INDEX namealgoindex ON tsigkeys(name, algorithm);


CREATE TABLE comments (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               VARCHAR(65535) NOT NULL,
  CONSTRAINT domain_exists
  FOREIGN KEY(domain_id) REFERENCES domains(id)
  ON DELETE CASCADE,
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);

CREATE INDEX comments_domain_id_idx ON comments (domain_id);
CREATE INDEX comments_name_type_idx ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);
