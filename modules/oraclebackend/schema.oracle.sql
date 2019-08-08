-- THIS IS NOT PRODUCTION-QUALITY CODE
-- 
-- This database schema is meant to serve as documentation-by-example for how
-- certain things might be done. It has also been used for early testing of the
-- backend. It should not be deployed as-is.

CREATE SEQUENCE zones_id_seq;

CREATE TABLE Zones (
  id INTEGER CONSTRAINT pkey_zones PRIMARY KEY,
  name VARCHAR2(512) NOT NULL,
  type VARCHAR2(32) NOT NULL,
  last_check INTEGER,
  refresh NUMBER(10,0),
  serial NUMBER(10,0) DEFAULT 0 NOT NULL,
  notified_serial NUMBER(10,0),
  CONSTRAINT chk_zones_name CHECK (name = lower(name)),
  CONSTRAINT unq_zones_name UNIQUE (name),
  CONSTRAINT chk_zones_type CHECK (
    type IN ('NATIVE', 'MASTER', 'SLAVE')
    AND (type = 'SLAVE' OR last_check IS NULL)
  ),
  CONSTRAINT chk_zones_serial CHECK (serial BETWEEN 0 AND 4294967295),
  CONSTRAINT chk_zones_nserial CHECK (notified_serial BETWEEN 0 AND 4294967295),
  CONSTRAINT chk_zones_refresh CHECK (refresh BETWEEN 0 AND 4294967295),
  CONSTRAINT chk_zones_master CHECK (type = 'MASTER' OR notified_serial IS NULL)
);

CREATE INDEX zones_type_ind ON Zones (type);


CREATE TABLE Zonemasters (
  zone_id INTEGER NOT NULL CONSTRAINT fkey_zonemasters_zones REFERENCES Zones ON DELETE CASCADE,
  master VARCHAR2(512) NOT NULL,
  CONSTRAINT unq_zonemasters_zone_master UNIQUE (zone_id, master)
);

CREATE INDEX zonemasters_zone_id_ind ON Zonemasters (zone_id);


CREATE TABLE ZoneAlsoNotify (
  zone_id INTEGER NOT NULL CONSTRAINT fkey_zonealsonotify_zones REFERENCES Zones ON DELETE CASCADE,
  hostaddr VARCHAR2(512) NOT NULL,
  CONSTRAINT unq_zonealsonotify_zone_host UNIQUE (zone_id, hostaddr)
);

CREATE INDEX zonealsonotify_zone_id_ind ON ZoneAlsoNotify (zone_id);


CREATE SEQUENCE supermasters_id_seq;

CREATE TABLE Supermasters (
  id INTEGER CONSTRAINT pkey_supermasters PRIMARY KEY,
  name VARCHAR2(64) NOT NULL,
  ip VARCHAR2(64) NOT NULL,
  nameserver VARCHAR2(512) NOT NULL
);

CREATE INDEX supermasters_ip_ind ON Supermasters (ip);


CREATE TABLE ZoneMetadata (
  zone_id INTEGER NOT NULL CONSTRAINT fkey_zonemetadata_zones REFERENCES Zones,
  meta_type VARCHAR2(64) NOT NULL,
  meta_ind INTEGER NOT NULL,
  meta_content VARCHAR2(4000),
  CONSTRAINT pkey_zonemetadata PRIMARY KEY (zone_id, meta_type, meta_ind)
);


CREATE SEQUENCE zonednskeys_id_seq;

CREATE TABLE ZoneDNSKeys (
  id INTEGER CONSTRAINT pkey_zonednskeys PRIMARY KEY,
  zone_id INTEGER NOT NULL CONSTRAINT fkey_zonednskeys_zones REFERENCES Zones,
  flags NUMBER(5,0) NOT NULL,
  active NUMBER(1,0) NOT NULL,
  keydata VARCHAR2(4000) NOT NULL,
  CONSTRAINT chk_zonednskeys_flags CHECK (flags BETWEEN 0 AND 65535),
  CONSTRAINT chk_zonednskeys_active CHECK (active IN (0, 1))
);

CREATE INDEX zonednskeys_zone_ind ON ZoneDNSKeys (zone_id);


CREATE TABLE TSIGKeys (
  name VARCHAR2(256),
  algorithm VARCHAR2(64) NOT NULL,
  secret VARCHAR2(2048) NOT NULL,
  CONSTRAINT chk_tsigkeys_name CHECK (name = lower(name)),
  CONSTRAINT chk_tsigkeys_algorithm CHECK (algorithm = lower(algorithm)),
  CONSTRAINT unq_tsigkeys_nav UNIQUE (name, algorithm, secret)
);


CREATE TABLE AccessControlList (
  acl_type VARCHAR2(64) NOT NULL,
  acl_key VARCHAR2(256) NOT NULL,
  acl_val VARCHAR2(2048),
  CONSTRAINT chk_acl_type CHECK (acl_type = 'allow-axfr'),
  CONSTRAINT unq_acl_tkv UNIQUE (acl_type, acl_key, acl_val)
);

CREATE INDEX acl_tk ON AccessControlList (acl_type, acl_key);


CREATE SEQUENCE records_id_seq;

CREATE TABLE Records (
  id INTEGER CONSTRAINT pkey_records PRIMARY KEY,
  zone_id INTEGER NOT NULL CONSTRAINT fkey_records_zones REFERENCES Zones,
  fqdn VARCHAR2(512) NOT NULL,
  revfqdn VARCHAR2(512) NOT NULL,
  fqdnhash VARCHAR2(512),
  ttl NUMBER(10,0) NOT NULL,
  type VARCHAR2(32),
  content VARCHAR2(2048),
  auth NUMBER(1,0) DEFAULT 1 NOT NULL,
  CONSTRAINT chk_records_fqdn CHECK (fqdn = lower(fqdn)),
  CONSTRAINT chk_records_ttl CHECK (ttl BETWEEN 0 AND 4294967295),
  CONSTRAINT chk_records_type CHECK (type = upper(type)),
  CONSTRAINT unq_records_zntc UNIQUE (zone_id, fqdn, type, content),
  CONSTRAINT chk_records_tc CHECK (
    content IS NOT NULL OR
    type IN('NS', 'CNAME') OR
    type IS NULL
  ),
  CONSTRAINT chk_records_auth CHECK (auth IN (0, 1))
);

CREATE INDEX records_zone_id_ind ON Records (zone_id);
CREATE INDEX records_revfqdn_ind ON Records (zone_id, revfqdn);
CREATE INDEX records_fqdnhash_ind ON Records (zone_id, fqdnhash);
CREATE INDEX records_last_change_ind ON Records (last_change);

-- Only one SOA and NSEC3PARAM record per zone
CREATE UNIQUE INDEX records_zonesoa_unq_ind ON Records (
  CASE
    WHEN type IN ('SOA', 'NSEC3PARAM') THEN zone_id
    ELSE NULL
  END,
  CASE
    WHEN type IN ('SOA', 'NSEC3PARAM') THEN type
    ELSE NULL
  END
);


CREATE FUNCTION label_reverse (dnsname IN VARCHAR2) RETURN VARCHAR2 AS
  pattern   VARCHAR2(32) := '[^.]+';
  match     BINARY_INTEGER := 1;
  label     VARCHAR2(63);
  out_dnsname  VARCHAR2(512);
BEGIN
  label := REGEXP_SUBSTR(dnsname, pattern, 1, match);
  match := match + 1;
  out_dnsname := label;
  LOOP
    label := REGEXP_SUBSTR(dnsname, pattern, 1, match);
    EXIT WHEN label IS NULL;
    out_dnsname := label || ' ' || out_dnsname;
    match := match + 1;
  END LOOP;
  RETURN(out_dnsname);
END;
/

SHOW ERRORS

CREATE FUNCTION dnsname_to_raw (in_dnsname IN VARCHAR2) RETURN RAW AS
  dnsname VARCHAR2(512) := LOWER(in_dnsname);
  rawname RAW(512);

  lpos BINARY_INTEGER := 1;
  rpos BINARY_INTEGER;
  label VARCHAR2(63);

  TYPE convarray IS VARRAY(64) OF RAW(1);
  byteval convarray := convarray(
    '00', '01', '02', '03', '04', '05', '06', '07',
    '08', '09', '0A', '0B', '0C', '0D', '0E', '0F',
    '10', '11', '12', '13', '14', '15', '16', '17',
    '18', '19', '1A', '1B', '1C', '1D', '1E', '1F',
    '20', '21', '22', '23', '24', '25', '26', '27',
    '28', '29', '2A', '2B', '2C', '2D', '2E', '2F',
    '30', '31', '32', '33', '34', '35', '36', '37',
    '38', '39', '3A', '3B', '3C', '3D', '3E', '3F'
  );
BEGIN
  IF dnsname IS NULL THEN
    RETURN('00');
  END IF;

  WHILE lpos <= LENGTH(dnsname) LOOP
    rpos := INSTR(dnsname, '.', lpos);
    IF rpos = 0 THEN
      rpos := LENGTH(dnsname) + 1;
    END IF;
    label := SUBSTR(dnsname, lpos, rpos - lpos);
    rawname := UTL_RAW.CONCAT(
      rawname,
      byteval(LENGTH(label) + 1),
      UTL_I18N.STRING_TO_RAW(label, 'US7ASCII')
    );
    lpos := rpos + 1;
  END LOOP;

  IF rpos = LENGTH(dnsname) THEN
    rawname := UTL_RAW.CONCAT(rawname, '00');
  END IF;

  RETURN(rawname);
END;
/

SHOW ERRORS

-- This is clearly terrible, though it appears to work.
-- For real deployment, you could upload the dnsjava
-- library into your database and use its facilities.
CREATE FUNCTION base32hex_encode (
  in_string RAW
) RETURN VARCHAR2 AS
  off BINARY_INTEGER := 1;
  out_string VARCHAR2(6554);
  sub RAW(5);
  num INTEGER;
  TYPE convarray IS VARRAY(32) OF VARCHAR2(1);
  digit convarray := convarray(
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v'
  );
BEGIN

  WHILE off + 4 <= UTL_RAW.LENGTH(in_string) LOOP
    sub := UTL_RAW.SUBSTR(in_string, off, 2);
    num := TO_NUMBER(sub, 'XXXX');
    out_string := out_string
      || digit(FLOOR(num / 2048) + 1)
      || digit(FLOOR(MOD(num / 64, 32)) + 1)
      || digit(FLOOR(MOD(num / 2, 32)) + 1);
    sub := UTL_RAW.SUBSTR(in_string, off + 1, 3);
    num := TO_NUMBER(sub, 'XXXXXX');
    out_string := out_string
      || digit(FLOOR(MOD(num / 4096, 32)) + 1)
      || digit(FLOOR(MOD(num / 128, 32)) + 1)
      || digit(FLOOR(MOD(num / 4, 32)) + 1);
    sub := UTL_RAW.SUBSTR(in_string, off + 3, 2);
    num := TO_NUMBER(sub, 'XXXX');
    out_string := out_string
      || digit(FLOOR(MOD(num / 32, 32)) + 1)
      || digit(FLOOR(MOD(num, 32)) + 1);
    off := off + 5;
  END LOOP;

  IF off <= UTL_RAW.LENGTH(in_string) THEN
    sub := UTL_RAW.SUBSTR(in_string, off);
    CASE UTL_RAW.LENGTH(sub)
      WHEN 1 THEN
        num := TO_NUMBER(sub, 'XX');
        out_string := out_string
          || digit(FLOOR(num / 8) + 1)
          || digit(FLOOR(MOD(num, 8)) * 4 + 1);
      WHEN 2 THEN
        num := TO_NUMBER(sub, 'XXXX');
        out_string := out_string
          || digit(FLOOR(num / 2048) + 1)
          || digit(FLOOR(MOD(num / 64, 32)) + 1)
          || digit(FLOOR(MOD(num / 2, 32)) + 1)
          || digit(FLOOR(MOD(num, 2)) * 16 + 1);
      WHEN 3 THEN
        num := TO_NUMBER(sub, 'XXXXXX');
        out_string := out_string
          || digit(FLOOR(num / 524288) + 1)
          || digit(FLOOR(MOD(num / 16384, 32)) + 1)
          || digit(FLOOR(MOD(num / 512, 32)) + 1)
          || digit(FLOOR(MOD(num / 16, 32)) + 1)
          || digit(FLOOR(MOD(num, 16)) * 2 + 1);
      WHEN 4 THEN
        num := TO_NUMBER(sub, 'XXXXXXXX');
        out_string := out_string
          || digit(FLOOR(num / 134217728) + 1)
          || digit(FLOOR(MOD(num / 4194304, 32)) + 1)
          || digit(FLOOR(MOD(num / 131072, 32)) + 1)
          || digit(FLOOR(MOD(num / 4096, 32)) + 1)
          || digit(FLOOR(MOD(num / 128, 32)) + 1)
          || digit(FLOOR(MOD(num / 4, 32)) + 1)
          || digit(FLOOR(MOD(num, 4)) * 8 + 1);
    END CASE;
  END IF;

  RETURN(out_string);
END;
/

SHOW ERRORS

CREATE FUNCTION dnsname_to_hashname (
  in_dnsname IN VARCHAR2,
  salt RAW,
  itercnt BINARY_INTEGER
) RETURN VARCHAR2 AS
  rawname RAW(512) := dnsname_to_raw(RTRIM(in_dnsname, '.') || '.');
  rawsalt RAW(32) := salt;
  hashname RAW(64);
  iter BINARY_INTEGER := 0;
BEGIN
  hashname := UTL_RAW.CONCAT(rawname, rawsalt);
  hashname := DBMS_CRYPTO.HASH(hashname, DBMS_CRYPTO.HASH_SH1);
  WHILE iter < itercnt LOOP
    hashname := UTL_RAW.CONCAT(hashname, rawsalt);
    hashname := DBMS_CRYPTO.HASH(hashname, DBMS_CRYPTO.HASH_SH1);
    iter := iter + 1;
  END LOOP;
  RETURN(base32hex_encode(hashname));
END;
/

SHOW ERRORS

CREATE PROCEDURE get_canonical_prev_next (
  in_zone_id INTEGER,
  in_fqdn VARCHAR2,
  out_prev OUT VARCHAR2,
  out_next OUT VARCHAR2
) AS
BEGIN
  SELECT * INTO out_prev
    FROM (
      SELECT fqdn
        FROM Records
        WHERE zone_id = in_zone_id
          AND revfqdn <= label_reverse(LOWER(in_fqdn))
          AND auth = 1
        ORDER BY revfqdn DESC
    ) WHERE ROWNUM = 1;

  BEGIN
    SELECT * INTO out_next
      FROM (
        SELECT fqdn
          FROM Records
          WHERE zone_id = in_zone_id
            AND revfqdn > label_reverse(LOWER(in_fqdn))
            AND auth = 1
          ORDER BY revfqdn ASC
      ) WHERE ROWNUM = 1;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      SELECT name INTO out_next
        FROM Zones
        WHERE id = in_zone_id;
  END;
END;
/

SHOW ERRORS

CREATE PROCEDURE get_hashed_prev_next (
  in_zone_id INTEGER,
  in_fqdnhash VARCHAR2,
  out_fqdn OUT VARCHAR2,
  out_prev OUT VARCHAR2,
  out_next OUT VARCHAR2
) AS
BEGIN
  BEGIN
    SELECT * INTO out_prev, out_fqdn
      FROM (
        SELECT fqdnhash, fqdn
          FROM Records
          WHERE zone_id = in_zone_id
            AND fqdnhash <= in_fqdnhash
            AND auth = 1
          ORDER BY fqdnhash DESC
      ) WHERE ROWNUM = 1;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      SELECT * INTO out_prev, out_fqdn
        FROM (
          SELECT fqdnhash, fqdn
            FROM Records
            WHERE zone_id = in_zone_id
              AND auth = 1
            ORDER BY fqdnhash DESC
        ) WHERE ROWNUM = 1;
  END;

  BEGIN
    SELECT * INTO out_next
      FROM (
        SELECT fqdnhash
          FROM Records
          WHERE zone_id = in_zone_id
            AND fqdnhash > in_fqdnhash
            AND auth = 1
          ORDER BY fqdnhash ASC
      ) WHERE ROWNUM = 1;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      SELECT * INTO out_next
        FROM (
          SELECT fqdnhash 
            FROM Records
            WHERE zone_id = in_zone_id
              AND auth = 1
            ORDER BY fqdnhash ASC
        ) WHERE ROWNUM = 1;
  END;
END;
/

SHOW ERRORS

CREATE TRIGGER records_fill_columns
  BEFORE INSERT OR UPDATE ON Records
  FOR EACH ROW
BEGIN
  -- 'www.site.example' => 'example site www' for NSEC ordering
  :NEW.revfqdn := label_reverse(LOWER(:NEW.fqdn));

  -- Hash the FQDN for NSEC3 ordering
  IF :NEW.type != 'RRSIG' THEN
    DECLARE
      nsec3param_string VARCHAR2(512);
      nsec3param_pattern VARCHAR2(512) := '^(\d+) +(\d+) +(\d+) +([0-9A-Fa-f]+)';
      hashalgo BINARY_INTEGER;
      itcount BINARY_INTEGER;
      salt RAW(256);
    BEGIN
      SELECT meta_content INTO nsec3param_string
      FROM ZoneMetadata
      WHERE zone_id = :NEW.zone_id
        AND meta_type = 'NSEC3PARAM';
      hashalgo := REGEXP_SUBSTR(nsec3param_string, nsec3param_pattern, 1, 1, '', 1);
      IF hashalgo != 1 THEN
        RAISE_APPLICATION_ERROR(-20000, 'NSEC3 hash is not SHA-1');
      END IF;
      itcount := REGEXP_SUBSTR(nsec3param_string, nsec3param_pattern, 1, 1, '', 3);
      salt := REGEXP_SUBSTR(nsec3param_string, nsec3param_pattern, 1, 1, '', 4);
      :NEW.fqdnhash := dnsname_to_hashname(:NEW.fqdn, salt, itcount);
    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        NULL;
    END;
  END IF;
END;
/

SHOW ERRORS

CREATE TRIGGER parse_zone_defining_records
  AFTER INSERT OR UPDATE ON Records
  FOR EACH ROW
  WHEN (NEW.type IN ('SOA'))
BEGIN
  CASE :NEW.type
    WHEN 'SOA' THEN
      DECLARE
        pattern      VARCHAR2(32) := '^[^ ]+ +[^ ]+ +(\d+) +(\d+)';
        serial_str   VARCHAR2(32) := REGEXP_SUBSTR(:NEW.content, pattern, 1, 1, '', 1);
        serial_num   NUMBER(10,0) := TO_NUMBER(serial_str);
        refresh_str  VARCHAR2(32) := REGEXP_SUBSTR(:NEW.content, pattern, 1, 1, '', 2);
      BEGIN
        IF serial_num = 0 THEN
          SELECT NVL(max(last_change), 0) INTO serial_num
          FROM Records
          WHERE zone_id = :NEW.zone_id;
        END IF;

        UPDATE Zones
        SET serial = serial_num, refresh = TO_NUMBER(refresh_str)
        WHERE id = :NEW.zone_id;
      END;
  END CASE;
END;
/

SHOW ERRORS

-- End of schema
-- vi: set sw=2 et : --
