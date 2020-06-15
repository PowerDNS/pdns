CREATE INDEX records_lookup_idx ON records(name, type);
CREATE INDEX records_lookup_id_idx ON records(domain_id, name, type);
CREATE INDEX records_order_idx ON records(domain_id, ordername);

DROP INDEX IF EXISTS rec_name_index;
DROP INDEX IF EXISTS nametype_index;
DROP INDEX IF EXISTS domain_id;
DROP INDEX IF EXISTS orderindex;

CREATE INDEX comments_idx ON comments(domain_id, name, type);

DROP INDEX IF EXISTS comments_domain_id_index;
DROP INDEX IF EXISTS comments_nametype_index;

ANALYZE;
