create table domains (
 id		 SERIAL PRIMARY KEY,
 name		 VARCHAR(255) NOT NULL,
 master		 VARCHAR(128) DEFAULT NULL,
 last_check	 INT DEFAULT NULL,
 type		 VARCHAR(6) NOT NULL,
 notified_serial INT DEFAULT NULL, 
 account         VARCHAR(40) DEFAULT NULL
);
CREATE UNIQUE INDEX name_index ON domains(name);
  
CREATE TABLE records (
        id              SERIAL PRIMARY KEY,
        domain_id       INT DEFAULT NULL,
        name            VARCHAR(255) DEFAULT NULL,
        type            VARCHAR(10) DEFAULT NULL,
        content         VARCHAR(358) DEFAULT NULL,
        ttl             INT DEFAULT NULL,
        prio            INT DEFAULT NULL,
        change_date     INT DEFAULT NULL, 
        CONSTRAINT domain_exists 
        FOREIGN KEY(domain_id) REFERENCES domains(id)
        ON DELETE CASCADE
);

CREATE INDEX rec_name_index ON records(name);
CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);

create table supermasters (
	  ip VARCHAR(25) NOT NULL, 
	  nameserver VARCHAR(255) NOT NULL, 
	  account VARCHAR(40) DEFAULT NULL
);

-- GRANT SELECT ON supermasters TO pdns;
-- GRANT ALL ON domains TO pdns;
-- GRANT ALL ON domains_id_seq TO pdns;
-- GRANT ALL ON records TO pdns;
-- GRANT ALL ON records_id_seq TO pdns;

	
