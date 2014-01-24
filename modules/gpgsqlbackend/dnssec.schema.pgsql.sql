alter table records add ordername   VARCHAR(255);
alter table records add auth bool;
create index recordorder on records (domain_id, ordername text_pattern_ops);

create table domainmetadata (
 id         SERIAL PRIMARY KEY,
 domain_id  INT REFERENCES domains(id) ON DELETE CASCADE,
 kind       VARCHAR(16),
 content    TEXT
);

create index domainidmetaindex on domainmetadata(domain_id);


create table cryptokeys (
 id         SERIAL PRIMARY KEY,
 domain_id  INT REFERENCES domains(id) ON DELETE CASCADE,
 flags      INT NOT NULL,
 active     BOOL,
 content    TEXT
);
create index domainidindex on cryptokeys(domain_id);


create table tsigkeys (
 id         SERIAL PRIMARY KEY,
 name       VARCHAR(255),
 algorithm  VARCHAR(50),
 secret     VARCHAR(255),
 constraint c_lowercase_name check (((name)::text = lower((name)::text)))
);

create unique index namealgoindex on tsigkeys(name, algorithm);

alter table records alter column type type VARCHAR(10);
