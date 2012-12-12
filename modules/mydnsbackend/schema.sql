--
--  Table layouts for mydns 1.1.0 (Mar 2012)
--  Copyright (C) 2002-2005 Don Moore
--
--  You might create these tables with a command like:
--
--    $ mydns --create-tables | mysql -hHOST -p -uUSER DATABASE
--
--

--
--  Table structure for table 'soa' (zones of authority)
--
CREATE TABLE IF NOT EXISTS soa (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  origin     CHAR(255) NOT NULL,
  ns         CHAR(255) NOT NULL,
  mbox       CHAR(255) NOT NULL,
  serial     INT UNSIGNED NOT NULL default '1',
  refresh    INT UNSIGNED NOT NULL default '28800',
  retry      INT UNSIGNED NOT NULL default '7200',
  expire     INT UNSIGNED NOT NULL default '604800',
  minimum    INT UNSIGNED NOT NULL default '86400',
  ttl        INT UNSIGNED NOT NULL default '86400',
  UNIQUE KEY (origin)
);

--
--  Table structure for table 'rr' (resource records)
--
CREATE TABLE IF NOT EXISTS rr (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  zone       INT UNSIGNED NOT NULL,
  name       CHAR(64) NOT NULL,
  type       ENUM('A','AAAA','CNAME','HINFO','MX','NAPTR','NS','PTR','RP','SRV','TXT'),
  data       CHAR(128) NOT NULL,
  aux        INT UNSIGNED NOT NULL,
  ttl        INT UNSIGNED NOT NULL default '86400',
  UNIQUE KEY rr (zone,name,type,data,aux)
);

