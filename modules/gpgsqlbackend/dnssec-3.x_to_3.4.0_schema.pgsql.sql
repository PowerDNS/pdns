/* Uncomment next 2 lines for versions <= 3.3 */
/* ALTER TABLE domains ADD CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT))); */
/* ALTER TABLE tsigkeys ADD CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT))); */

ALTER TABLE records ADD disabled BOOL DEFAULT 'f';
ALTER TABLE records ALTER COLUMN content TYPE VARCHAR(65535);
ALTER TABLE records ALTER COLUMN auth SET DEFAULT 't';
ALTER TABLE records ALTER COLUMN type TYPE VARCHAR(10);
ALTER TABLE supermasters ALTER COLUMN ip TYPE INET USING ip::INET;
ALTER TABLE supermasters ALTER COLUMN account SET DEFAULT NOT NULL;
ALTER TABLE supermasters ADD CONSTRAINT supermasters_pkey PRIMARY KEY (ip, nameserver);
ALTER TABLE domainmetadata ALTER COLUMN kind TYPE VARCHAR(32);
ALTER TABLE tsigkeys ALTER COLUMN algorithm TYPE VARCHAR(50);

CREATE INDEX recordorder ON records (domain_id, ordername text_pattern_ops);
DROP INDEX IF EXISTS orderindex;


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
