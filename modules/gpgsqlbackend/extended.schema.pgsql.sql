create table domainmetadata (
 id         SERIAL PRIMARY KEY,
 domain_id  INT REFERENCES domains(id) ON DELETE CASCADE,
 kind       VARCHAR(16),
 content    TEXT
);

create index domainidmetaindex on domainmetadata(domain_id);

-- GRANT ALL ON domainmetadata TO pdns;
-- GRANT ALL ON domainmetadata_id_seq TO pdns;


create table tsigkeys (
 id         SERIAL PRIMARY KEY,
 name       VARCHAR(255),
 algorithm  VARCHAR(50),
 secret     VARCHAR(255),
 constraint c_lowercase_name check (((name)::text = lower((name)::text)))
);

create unique index namealgoindex on tsigkeys(name, algorithm);

-- GRANT ALL ON tsigkeys TO pdns;
-- GRANT ALL ON tsigkeys_id_seq TO pdns;
