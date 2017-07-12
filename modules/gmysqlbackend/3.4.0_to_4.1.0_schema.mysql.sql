ALTER TABLE domains MODIFY account VARCHAR(40) CHARACTER SET 'utf8' DEFAULT NULL;
ALTER TABLE domains CHARACTER SET 'latin1';

ALTER TABLE records MODIFY id BIGINT AUTO_INCREMENT;
ALTER TABLE records CHARACTER SET 'latin1';
CREATE INDEX ordername ON records (ordername);
DROP INDEX recordorder ON records;

ALTER TABLE supermasters MODIFY account VARCHAR(40) CHARACTER SET 'utf8' NOT NULL;
ALTER TABLE supermasters CHARACTER SET 'latin1';

ALTER TABLE comments MODIFY account VARCHAR(40) CHARACTER SET 'utf8' DEFAULT NULL;
ALTER TABLE comments MODIFY comment TEXT CHARACTER SET 'utf8' NOT NULL;
ALTER TABLE comments CHARACTER SET 'latin1';
DROP INDEX comments_domain_id_idx ON comments;

ALTER TABLE domainmetadata CHARACTER SET 'latin1';

ALTER TABLE cryptokeys CHARACTER SET 'latin1';

ALTER TABLE tsigkeys CHARACTER SET 'latin1';
