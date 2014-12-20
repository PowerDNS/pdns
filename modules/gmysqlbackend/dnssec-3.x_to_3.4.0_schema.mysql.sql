/* Uncomment next 3 lines for versions <= 3.1 */
/* DROP INDEX rec_name_index ON records; */
/* DROP INDEX orderindex ON records; */
/* CREATE INDEX recordorder ON records (domain_id, ordername); */

ALTER TABLE records ADD disabled TINYINT(1) DEFAULT 0 AFTER change_date;
ALTER TABLE records MODIFY content VARCHAR(64000) DEFAULT NULL;
ALTER TABLE records MODIFY ordername VARCHAR(255) BINARY DEFAULT NULL;
ALTER TABLE records MODIFY auth TINYINT(1) DEFAULT 1;
ALTER TABLE records MODIFY type VARCHAR(10);
ALTER TABLE supermasters MODIFY ip VARCHAR(64) NOT NULL;
ALTER TABLE supermasters ADD PRIMARY KEY(ip, nameserver);
ALTER TABLE supermasters MODIFY account VARCHAR(40) NOT NULL;
ALTER TABLE domainmetadata MODIFY kind VARCHAR(32);
ALTER TABLE tsigkeys MODIFY algorithm VARCHAR(50);
ALTER TABLE domainmetadata ENGINE=InnoDB;
ALTER TABLE cryptokeys ENGINE=InnoDB;
ALTER TABLE tsigkeys ENGINE=InnoDB;

DROP INDEX domainmetaidindex ON domainmetadata;
CREATE INDEX domainmetadata_idx ON domainmetadata (domain_id, kind);

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
