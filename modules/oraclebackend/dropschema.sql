DROP PROCEDURE get_hashed_prev_next;
DROP PROCEDURE get_canonical_prev_next;

DROP FUNCTION dnsname_to_hashname;
DROP FUNCTION base32hex_encode;
DROP FUNCTION dnsname_to_raw;
DROP FUNCTION label_reverse;

DROP TABLE Records;
DROP SEQUENCE records_id_seq;
DROP TABLE AccessControlList;
DROP TABLE TSIGKeys;
DROP TABLE ZoneDNSKeys;
DROP SEQUENCE zonednskeys_id_seq;
DROP TABLE ZoneMetadata;
DROP TABLE Supermasters;
DROP SEQUENCE supermasters_id_seq;
DROP TABLE Zonemasters;
DROP TABLE ZoneAlsoNotifyHosts;
DROP TABLE Zones;
DROP SEQUENCE zones_id_seq;

-- vi: set sw=2 et : --
