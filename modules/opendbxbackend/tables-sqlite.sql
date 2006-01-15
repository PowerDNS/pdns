CREATE TABLE domains (
	id INT AUTOINCREMENT,
	type VARCHAR(6) NOT NULL,
	name VARCHAR(255) NOT NULL,
	master VARCHAR(40) DEFAULT NULL,
	account VARCHAR(40) DEFAULT NULL,
	notified_serial INT DEFAULT NULL,
	last_check INT DEFAULT NULL,
CONSTRAINT pk_id
	PRIMARY KEY (id),
CONSTRAINT unq_name
	UNIQUE (name)
);


CREATE TABLE records (
	id INT AUTOINCREMENT,
	domain_id INT DEFAULT NULL,
	name VARCHAR(255) DEFAULT NULL,
	type VARCHAR(6) DEFAULT NULL,
	ttl INT DEFAULT NULL,
	prio INT DEFAULT NULL,
	content VARCHAR(255) DEFAULT NULL,
	change_date INT DEFAULT NULL,
CONSTRAINT pk_id
	PRIMARY KEY (id),
CONSTRAINT fk_domainid
	FOREIGN KEY (domain_id)
	REFERENCES domains(id)
	ON UPDATE CASCADE
	ON DELETE CASCADE
);

CREATE INDEX idx_rname ON records(name);
CREATE INDEX idx_rname_rtype ON records(name,type);
CREATE INDEX idx_rdomainid ON records(domain_id);


CREATE TABLE supermasters (
	ip VARCHAR(40) NOT NULL,
	nameserver VARCHAR(255) NOT NULL,
	account VARCHAR(40) DEFAULT NULL
);
