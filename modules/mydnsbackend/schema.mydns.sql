--
--  Table layouts for mydns 1.2.8.31 (Dec 2014)
--  Copyright (C) 2002-2005 Don Moore  2007-2008 Howard Wilkinson
--
--  You might create these tables with a command like:
--
--    $ mydns --create-tables | mysql -hHOST -p -uUSER DATABASE
--
-- Originally licensed under the GNU GPLv2 or higher

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
   active     ENUM('Y', 'N') NOT NULL DEFAULT 'Y',
  UNIQUE KEY (origin)
) Engine=MyISAM;

--
--  Table structure for table 'rr' (resource records)
--
CREATE TABLE IF NOT EXISTS rr (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  zone       INT UNSIGNED NOT NULL,
  name       CHAR(200) NOT NULL,
  data       VARBINARY(128) NOT NULL,
  aux        INT UNSIGNED NOT NULL,
  ttl        INT UNSIGNED NOT NULL default '86400',
  type       ENUM('A','AAAA','CNAME','HINFO','MX','NAPTR','NS','PTR','RP','SRV','TXT'),
  active     ENUM('Y', 'N') NOT NULL DEFAULT 'Y',
  UNIQUE KEY rr (zone,name,type,data,aux,active)
) Engine=MyISAM;
