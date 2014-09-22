/* Uncomment next line for versions <= 3.1 */
/* DROP INDEX rec_name_index ON records; */

ALTER TABLE records ADD disabled TINYINT(1) DEFAULT 0;
ALTER TABLE records MODIFY content VARCHAR(64000) DEFAULT NULL;
ALTER TABLE records ADD ordername VARCHAR(255) BINARY DEFAULT NULL;
ALTER TABLE records ADD auth TINYINT(1) DEFAULT 1;
ALTER TABLE records MODIFY type VARCHAR(10);
ALTER TABLE supermasters MODIFY ip VARCHAR(64) NOT NULL;
ALTER TABLE supermasters MODIFY account VARCHAR(40) NOT NULL;
ALTER TABLE supermasters ADD PRIMARY KEY(ip, nameserver);

CREATE INDEX recordorder ON records (domain_id, ordername);


CREATE TABLE domainmetadata (
  id                    INT AUTO_INCREMENT,
  domain_id             INT NOT NULL,
  kind                  VARCHAR(32),
  content               TEXT,
  PRIMARY KEY(id)
) Engine=InnoDB;

CREATE INDEX domainmetadata_idx ON domainmetadata (domain_id, kind);


CREATE TABLE cryptokeys (
  id                    INT AUTO_INCREMENT,
  domain_id             INT NOT NULL,
  flags                 INT NOT NULL,
  active                TINYINT(1),
  content               TEXT,
  PRIMARY KEY(id)
) Engine=InnoDB;

CREATE INDEX domainidindex ON cryptokeys(domain_id);


CREATE TABLE tsigkeys (
  id                    INT AUTO_INCREMENT,
  name                  VARCHAR(255),
  algorithm             VARCHAR(50),
  secret                VARCHAR(255),
  PRIMARY KEY(id)
) Engine=InnoDB;

CREATE UNIQUE INDEX namealgoindex ON tsigkeys(name, algorithm);


CREATE TABLE comments (
  id                    INT AUTO_INCREMENT,
  domain_id             INT NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) NOT NULL,
  comment               VARCHAR(64000) NOT NULL,
  PRIMARY KEY(id)
) Engine=InnoDB;

CREATE INDEX comments_domain_id_idx ON comments (domain_id);
CREATE INDEX comments_name_type_idx ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);
