CREATE TABLE "domains" (
	"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	"name" VARCHAR(255) NOT NULL,
	"type" VARCHAR(6) NOT NULL,
	"master" VARCHAR(40) NOT NULL DEFAULT '',
	"account" VARCHAR(40) NOT NULL DEFAULT '',
	"notified_serial" INTEGER DEFAULT NULL,
	"last_check" INTEGER DEFAULT NULL,
	"status" CHAR(1) NOT NULL DEFAULT 'A',
CONSTRAINT "unq_domains_name"
	UNIQUE ("name")
);

CREATE INDEX "idx_domains_status_type" ON "domains" ("status","type");



CREATE TABLE "records" (
	"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	"domain_id" INTEGER NOT NULL,
	"name" VARCHAR(255) NOT NULL,
	"type" VARCHAR(6) NOT NULL,
	"ttl" INTEGER DEFAULT NULL,
	"prio" INTEGER DEFAULT NULL,
	"content" VARCHAR(255) NOT NULL,
	"change_date" INTEGER DEFAULT NULL,
CONSTRAINT "fk_records_domainid"
	FOREIGN KEY ("domain_id")
	REFERENCES "domains" ("id")
	ON UPDATE CASCADE
	ON DELETE CASCADE
);

CREATE INDEX "idx_records_name_type" ON "records" ("name","type");
CREATE INDEX "idx_records_type" ON "records" ("type");



CREATE TABLE "supermasters" (
	"ip" VARCHAR(40) NOT NULL,
	"nameserver" VARCHAR(255) NOT NULL,
	"account" VARCHAR(40) NOT NULL DEFAULT ''
);

CREATE INDEX "idx_smip_smns" ON "supermasters" ("ip","nameserver");



GRANT SELECT ON "supermasters" TO "powerdns";
GRANT ALL ON "domains" TO "powerdns";
GRANT ALL ON "records" TO "powerdns";
