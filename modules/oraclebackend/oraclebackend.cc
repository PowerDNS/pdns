/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 * originally authored by Maik Zumstrull
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string>
#include <stdexcept>

#include "pdns/namespaces.hh"

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "oraclebackend.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/lock.hh"

#include <oci.h>

static const char *basicQueryKey = "PDNS_Basic_Query";
static const char *basicQueryDefaultAuthSQL =
  "SELECT fqdn, ttl, type, content, zone_id, auth "
  "FROM Records "
  "WHERE type = :type AND fqdn = lower(:name)";

static const char *basicQueryDefaultSQL = "SELECT fqdn, ttl, type, content, zone_id, "
  "FROM Records "
  "WHERE type = :type AND fqdn = lower(:name)";

static const char *basicIdQueryKey = "PDNS_Basic_Id_Query";
static const char *basicIdQueryDefaultAuthSQL =
  "SELECT fqdn, ttl, type, content, zone_id, auth "
  "FROM Records "
  "WHERE type = :type AND fqdn = lower(:name) AND zone_id = :zoneid";

static const char *basicIdQueryDefaultSQL = 
  "SELECT fqdn, ttl, type, content, zone_id, "
  "FROM Records "
  "WHERE type = :type AND fqdn = lower(:name) AND zone_id = :zoneid";

static const char *anyQueryKey = "PDNS_ANY_Query";
static const char *anyQueryDefaultAuthSQL =
  "SELECT fqdn, ttl, type, content, zone_id, auth "
  "FROM Records "
  "WHERE fqdn = lower(:name)"
  "  AND type IS NOT NULL "
  "ORDER BY type";

static const char *anyQueryDefaultSQL =
  "SELECT fqdn, ttl, type, content, zone_id, "
  "FROM Records "
  "WHERE fqdn = lower(:name)"
  "  AND type IS NOT NULL "
  "ORDER BY type";

static const char *anyIdQueryKey = "PDNS_ANY_Id_Query";
static const char *anyIdQueryDefaultAuthSQL =
  "SELECT fqdn, ttl, type, content, zone_id, auth "
  "FROM Records "
  "WHERE fqdn = lower(:name)"
  "  AND zone_id = :zoneid"
  "  AND type IS NOT NULL "
  "ORDER BY type";

static const char *anyIdQueryDefaultSQL =
  "SELECT fqdn, ttl, type, content, zone_id, "
  "FROM Records "
  "WHERE fqdn = lower(:name)"
  "  AND zone_id = :zoneid"
  "  AND type IS NOT NULL "
  "ORDER BY type";


static const char *listQueryKey = "PDNS_List_Query";
static const char *listQueryDefaultAuthSQL =
  "SELECT fqdn, ttl, type, content, zone_id, auth "
  "FROM Records "
  "WHERE zone_id = :zoneid"
  "  AND type IS NOT NULL "
  "ORDER BY fqdn, type";

static const char *listQueryDefaultSQL =
  "SELECT fqdn, ttl, type, content, zone_id, "
  "FROM Records "
  "WHERE zone_id = :zoneid"
  "  AND type IS NOT NULL "
  "ORDER BY fqdn, type";


static const char *zoneInfoQueryKey = "PDNS_Zone_Info_Query";
static const char *zoneInfoQueryDefaultSQL =
  "SELECT id, name, type, last_check, serial, notified_serial "
  "FROM Zones "
  "WHERE name = lower(:name)";

static const char *alsoNotifyQueryKey = "PDNS_Also_Notify_Query";
static const char *alsoNotifyQueryDefaultSQL =
  "SELECT an.hostaddr "
  "FROM Zones z JOIN ZoneAlsoNotify an ON z.id = an.zone_id "
  "WHERE z.name = lower(:name)";

static const char *zoneMastersQueryKey = "PDNS_Zone_Masters_Query";
static const char *zoneMastersQueryDefaultSQL =
  "SELECT master "
  "FROM Zonemasters "
  "WHERE zone_id = :zoneid";

static const char *deleteZoneQueryKey = "PDNS_Delete_Zone_Query";
static const char *deleteZoneQueryDefaultSQL =
  "DELETE FROM Records WHERE zone_id = :zoneid";

static const char *zoneSetLastCheckQueryKey = "PDNS_Zone_Set_Last_Check_Query";
static const char *zoneSetLastCheckQueryDefaultSQL =
  "UPDATE Zones SET last_check = :lastcheck WHERE id = :zoneid";

static const char *zoneSetNotifiedSerialQueryKey = "PDNS_Zone_Set_NSerial_Query";
static const char *zoneSetNotifiedSerialQueryDefaultSQL =
  "UPDATE Zones SET notified_serial = :serial WHERE id = :zoneid";

static const char *insertRecordQueryKey = "PDNS_Insert_Record_Query";
static const char *insertRecordQueryDefaultSQL =
  "INSERT INTO Records (id, fqdn, zone_id, ttl, type, content) "
  "VALUES (records_id_seq.NEXTVAL, lower(:name), :zoneid, :ttl, :type, :content)";

static const char *finalizeAXFRQueryKey = "PDNS_Finalize_AXFR";
static const char *finalizeAXFRQueryDefaultSQL =
  "DECLARE\n"
  "  zone_id INTEGER := :zoneid;\n"
  "BEGIN\n"
  "  NULL;\n"
  "END;";

static const char *unfreshZonesQueryKey = "PDNS_Unfresh_Zones_Query";
static const char *unfreshZonesQueryDefaultSQL =
  "SELECT z.id, z.name, z.last_check, z.serial, zm.master "
  "FROM Zones z JOIN Zonemasters zm ON z.id = zm.zone_id "
  "WHERE z.type = 'SLAVE' "
  "  AND (z.last_check IS NULL OR z.last_check + z.refresh < :ts)"
  "ORDER BY z.id";

static const char *updatedMastersQueryKey = "PDNS_Updated_Masters_Query";
static const char *updatedMastersQueryDefaultSQL =
  "SELECT id, name, serial, notified_serial "
  "FROM Zones "
  "WHERE type = 'MASTER' "
  "AND (notified_serial IS NULL OR notified_serial < serial)";

static const char *acceptSupernotificationQueryKey = "PDNS_Accept_Supernotification_Query";
static const char *acceptSupernotificationQueryDefaultSQL =
  "SELECT name "
  "FROM Supermasters "
  "WHERE ip = :ip AND nameserver = lower(:ns)";

static const char *insertSlaveQueryKey = "PDNS_Insert_Slave_Query";
static const char *insertSlaveQueryDefaultSQL =
  "INSERT INTO Zones (id, name, type) "
  "VALUES (zones_id_seq.NEXTVAL, lower(:zone), 'SLAVE') "
  "RETURNING id INTO :zoneid";

static const char *insertMasterQueryKey = "PDNS_Insert_Master_Query";
static const char *insertMasterQueryDefaultSQL =
  "INSERT INTO Zonemasters (zone_id, master) "
  "VALUES (:zoneid, :ip)";

static const char *prevNextNameQueryKey = "PDNS_Prev_Next_Name_Query";
static const char *prevNextNameQueryDefaultSQL =
  "BEGIN\n"
  "  get_canonical_prev_next(:zoneid, :name, :prev, :next);\n"
  "END;";

static const char *prevNextHashQueryKey = "PDNS_Prev_Next_Hash_Query";
static const char *prevNextHashQueryDefaultSQL =
  "BEGIN\n"
  "  get_hashed_prev_next(:zoneid, :hash, :unhashed, :prev, :next);\n"
  "END;";

static const char *getAllZoneMetadataQueryKey = "PDNS_Get_All_Zone_Metadata";
static const char *getAllZoneMetadataQueryDefaultSQL =
  "SELECT md.meta_type, md.meta_content "
  "FROM Zones z JOIN ZoneMetadata md ON z.id = md.zone_id "
  "WHERE z.name = lower(:name) "
  "ORDER BY md.meta_ind";

static const char *getZoneMetadataQueryKey = "PDNS_Get_Zone_Metadata";
static const char *getZoneMetadataQueryDefaultSQL =
  "SELECT md.meta_content "
  "FROM Zones z JOIN ZoneMetadata md ON z.id = md.zone_id "
  "WHERE z.name = lower(:name) AND md.meta_type = :kind "
  "ORDER BY md.meta_ind";

static const char *delZoneMetadataQueryKey = "PDNS_Del_Zone_Metadata";
static const char *delZoneMetadataQueryDefaultSQL =
  "DELETE FROM ZoneMetadata md "
  "WHERE zone_id = (SELECT id FROM Zones z WHERE z.name = lower(:name)) "
  "  AND md.meta_type = :kind";

static const char *setZoneMetadataQueryKey = "PDNS_Set_Zone_Metadata";
static const char *setZoneMetadataQueryDefaultSQL =
  "INSERT INTO ZoneMetadata (zone_id, meta_type, meta_ind, meta_content) "
  "VALUES ("
  "  (SELECT id FROM Zones WHERE name = lower(:name)),"
  "  :kind, :i, :content"
  ")";

static const char *getTSIGKeyQueryKey = "PDNS_Get_TSIG_Key";
static const char *getTSIGKeyQueryDefaultSQL =
  "SELECT algorithm, secret "
  "FROM TSIGKeys "
  "WHERE name = :name";

static const char *delTSIGKeyQueryKey = "PDNS_Del_TSIG_Key";
static const char *delTSIGKeyQueryDefaultSQL =
  "DELETE FROM TSIGKeys "
  "WHERE name = :name";

static const char *setTSIGKeyQueryKey = "PDNS_Set_TSIG_Key";
static const char *setTSIGKeyQueryDefaultSQL =
  "INSERT INTO TSIGKeys (name, algorithm, secret) "
  "VALUES (:name, :algorithm, :secret)";

static const char *getTSIGKeysQueryKey = "PDNS_Get_TSIG_Keys";
static const char *getTSIGKeysQueryDefaultSQL =
  "SELECT name, algorithm, secret "
  "FROM TSIGKeys";

static const char *getZoneKeysQueryKey = "PDNS_Get_Zone_Keys";
static const char *getZoneKeysQueryDefaultSQL =
  "SELECT k.id, k.flags, k.active, k.keydata "
  "FROM ZoneDNSKeys k JOIN Zones z ON z.id = k.zone_id "
  "WHERE z.name = lower(:name)";

static const char *delZoneKeyQueryKey = "PDNS_Del_Zone_Key";
static const char *delZoneKeyQueryDefaultSQL =
  "DELETE FROM ZoneDNSKeys WHERE id = :keyid";

static const char *addZoneKeyQueryKey = "PDNS_Add_Zone_Key";
static const char *addZoneKeyQueryDefaultSQL =
  "INSERT INTO ZoneDNSKeys (id, zone_id, flags, active, keydata) "
  "VALUES ("
  "  zonednskeys_id_seq.NEXTVAL,"
  "  (SELECT id FROM Zones WHERE name = lower(:name)),"
  "  :flags,"
  "  :active,"
  "  :content"
  ") RETURNING id INTO :keyid";

static const char *setZoneKeyStateQueryKey = "PDNS_Set_Zone_Key_State";
static const char *setZoneKeyStateQueryDefaultSQL =
  "UPDATE ZoneDNSKeys SET active = :active WHERE id = :keyid";


static void
string_to_cbuf (char *buf, const string& s, size_t bufsize)
{
  if (s.size() >= bufsize) {
    throw std::overflow_error("OracleBackend: string does not fit into char buffer");
  }
  strncpy(buf, s.c_str(), bufsize);
}

static void
DNSName_to_cbuf (char *buf, const DNSName& n, size_t bufsize)
{
  string s = toLower(n.toStringNoDot());
  if (s.size() >= bufsize) {
    throw std::overflow_error("OracleBackend: DNSName does not fit into char buffer");
  }
  strncpy(buf, s.c_str(), bufsize);
}

OracleBackend::OracleBackend (const string &suffix, OCIEnv *envh,
                              char *poolname)
{
  setArgPrefix(string("oracle") + suffix);
  sword err;

  // Initialize everything in a known state
  oraenv = envh;
  oraerr = NULL;
  pooledSvcCtx = NULL;
  masterAuthHandle = NULL;
  masterSvcCtx = NULL;
  curStmtHandle = NULL;
  openTransactionZoneID = -1;

  try
  {
    d_dnssecQueries = mustDo("dnssec");
  }
  catch (ArgException e)
  {
    d_dnssecQueries = false;
  }

  // Process configuration options
  string_to_cbuf(myServerName, getArg("nameserver-name"), sizeof(myServerName));

  if (d_dnssecQueries) {
    basicQuerySQL = getArg("basic-query-auth");
    basicIdQuerySQL = getArg("basic-id-query-auth");
    anyQuerySQL = getArg("any-query-auth");
    anyIdQuerySQL = getArg("any-id-query-auth");
    listQuerySQL = getArg("list-query-auth");
  } else {
    basicQuerySQL = getArg("basic-query");
    basicIdQuerySQL = getArg("basic-id-query");
    anyQuerySQL = getArg("any-query");
    anyIdQuerySQL = getArg("any-id-query");
    listQuerySQL = getArg("list-query");
  }

  zoneInfoQuerySQL = getArg("zone-info-query");
  alsoNotifyQuerySQL = getArg("also-notify-query");
  zoneMastersQuerySQL = getArg("zone-masters-query");
  deleteZoneQuerySQL = getArg("delete-zone-query");
  zoneSetLastCheckQuerySQL = getArg("zone-set-last-check-query");
  insertRecordQuerySQL = getArg("insert-record-query");
  finalizeAXFRQuerySQL = getArg("finalize-axfr-query");
  unfreshZonesQuerySQL = getArg("unfresh-zones-query");
  updatedMastersQuerySQL = getArg("updated-masters-query");
  acceptSupernotificationQuerySQL = getArg("accept-supernotification-query");
  insertSlaveQuerySQL = getArg("insert-slave-query");
  insertMasterQuerySQL = getArg("insert-master-query");
  zoneSetNotifiedSerialQuerySQL = getArg("zone-set-notified-serial-query");
  prevNextNameQuerySQL = getArg("prev-next-name-query");
  prevNextHashQuerySQL = getArg("prev-next-hash-query");
  getAllZoneMetadataQuerySQL = getArg("get-all-zone-metadata-query");
  getZoneMetadataQuerySQL = getArg("get-zone-metadata-query");
  delZoneMetadataQuerySQL = getArg("del-zone-metadata-query");
  setZoneMetadataQuerySQL = getArg("set-zone-metadata-query");
  getTSIGKeyQuerySQL = getArg("get-tsig-key-query");
  delTSIGKeyQuerySQL = getArg("del-tsig-key-query");
  setTSIGKeyQuerySQL = getArg("set-tsig-key-query");
  getTSIGKeysQuerySQL = getArg("get-tsig-keys-query");
  getZoneKeysQuerySQL = getArg("get-zone-keys-query");
  delZoneKeyQuerySQL = getArg("del-zone-key-query");
  addZoneKeyQuerySQL = getArg("add-zone-key-query");
  setZoneKeyStateQuerySQL = getArg("set-zone-key-state-query");

  // Allocate an error handle
  err = OCIHandleAlloc(oraenv, (void**) &oraerr,
                       OCI_HTYPE_ERROR, 0, NULL);
  if (err == OCI_ERROR) {
    throw OracleException("OCIHandleAlloc");
  }

  // Logon to the database
  err = OCISessionGet(oraenv, oraerr, &pooledSvcCtx, NULL, (OraText*) poolname, strlen(poolname), NULL, 0, NULL, NULL, NULL, OCI_SESSGET_SPOOL);

  if (err == OCI_ERROR) {
    throw OracleException("Opening Oracle session", oraerr);
  }
}

void
OracleBackend::openMasterConnection ()
{
  sword err;

  if (masterSvcCtx == NULL) {
    err = OCIHandleAlloc(oraenv, (void**) &masterAuthHandle, OCI_HTYPE_AUTHINFO, 0, NULL);
    if (err == OCI_ERROR) {
      throw OracleException("openMasterConnection: allocating auth handle");
    }

    string database = getArg("master-database");
    string username = getArg("master-username");
    string password = getArg("master-password");

    err = OCIAttrSet(masterAuthHandle, OCI_HTYPE_AUTHINFO, (void*)username.c_str(), username.size(), OCI_ATTR_USERNAME, oraerr);
    if (err == OCI_ERROR) {
      throw OracleException("openMasterConnection: setting username");
    }

    err = OCIAttrSet(masterAuthHandle, OCI_HTYPE_AUTHINFO, (void*)password.c_str(), password.size(), OCI_ATTR_PASSWORD, oraerr);
    if (err == OCI_ERROR) {
      throw OracleException("openMasterConnection: setting password");
    }

    err = OCISessionGet(oraenv, oraerr, &masterSvcCtx, masterAuthHandle,
        (OraText*)database.c_str(), database.size(),
        NULL, 0, NULL, NULL, NULL, OCI_SESSGET_STMTCACHE);
    if (err == OCI_ERROR) {
      throw OracleException("openMasterConnection OCISessionGet");
    }
  }
}

OracleBackend::~OracleBackend ()
{
  Cleanup();
}

void
OracleBackend::lookup (const QType &qtype, const DNSName& qname,
                       DNSPacket *p, int zoneId)
{
  sword rc;

  if (qtype.getCode() != QType::ANY) {
    if (zoneId < 0) {
      if (curStmtHandle != NULL) throw OracleException("Invalid state");
      curStmtHandle = prepare_query(pooledSvcCtx, basicQuerySQL, basicQueryKey);
      curStmtKey = basicQueryKey;
      define_fwd_query(curStmtHandle);
      bind_str_failokay(curStmtHandle, ":nsname", myServerName, sizeof(myServerName));
      bind_str(curStmtHandle, ":name", mQueryName, sizeof(mQueryName));
      bind_str(curStmtHandle, ":type", mQueryType, sizeof(mQueryType));
    } else {
      if (curStmtHandle != NULL) throw OracleException("Invalid state");
      curStmtHandle = prepare_query(pooledSvcCtx, basicIdQuerySQL, basicIdQueryKey);
      curStmtKey = basicIdQueryKey;
      define_fwd_query(curStmtHandle);
      bind_str_failokay(curStmtHandle, ":nsname", myServerName, sizeof(myServerName));
      bind_str(curStmtHandle, ":name", mQueryName, sizeof(mQueryName));
      bind_str(curStmtHandle, ":type", mQueryType, sizeof(mQueryType));
      bind_int(curStmtHandle, ":zoneid", &mQueryZoneId);
    }
  } else {
    if (zoneId < 0) {
      if (curStmtHandle != NULL) throw OracleException("Invalid state");
      curStmtHandle = prepare_query(pooledSvcCtx, anyQuerySQL, anyQueryKey);
      curStmtKey = anyQueryKey;
      define_fwd_query(curStmtHandle);
      bind_str_failokay(curStmtHandle, ":nsname", myServerName, sizeof(myServerName));
      bind_str(curStmtHandle, ":name", mQueryName, sizeof(mQueryName));
    } else {
      if (curStmtHandle != NULL) throw OracleException("Invalid state");
      curStmtHandle = prepare_query(pooledSvcCtx, anyIdQuerySQL, anyIdQueryKey);
      curStmtKey = anyIdQueryKey;
      define_fwd_query(curStmtHandle);
      bind_str_failokay(curStmtHandle, ":nsname", myServerName, sizeof(myServerName));
      bind_str(curStmtHandle, ":name", mQueryName, sizeof(mQueryName));
      bind_int(curStmtHandle, ":zoneid", &mQueryZoneId);
    }
  }

  DNSName_to_cbuf(mQueryName, qname, sizeof(mQueryName));
  string_to_cbuf(mQueryType, qtype.getName(), sizeof(mQueryType));
  mQueryZoneId = zoneId;

  rc = OCIStmtExecute(pooledSvcCtx, curStmtHandle, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle Lookup", oraerr);
  }

  if (rc == OCI_NO_DATA) {
    release_query(curStmtHandle, curStmtKey);
    curStmtHandle = NULL;
  }
}

bool
OracleBackend::getBeforeAndAfterNames (
  uint32_t zoneId, const DNSName& zone,
  const DNSName& name, DNSName& before, DNSName& after)
{
  if(!d_dnssecQueries)
    return -1;

  sword rc;
  OCIStmt *stmt;

  (void)zone;

  stmt = prepare_query(pooledSvcCtx, prevNextNameQuerySQL, prevNextNameQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));
  bind_str_ind(stmt, ":prev", mResultPrevName, sizeof(mResultPrevName), &mResultPrevNameInd);
  bind_str_ind(stmt, ":next", mResultNextName, sizeof(mResultNextName), &mResultNextNameInd);
  bind_uint32(stmt, ":zoneid", &zoneId);
  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));
  mResultPrevNameInd = -1;
  mResultNextNameInd = -1;

  rc = OCIStmtExecute(pooledSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException(
      "Oracle getBeforeAndAfterNames", oraerr
    );
  }

  check_indicator(mResultPrevNameInd, false);
  check_indicator(mResultNextNameInd, false);

  before = DNSName(mResultPrevName);
  after = DNSName(mResultNextName);

  release_query(stmt, prevNextNameQueryKey);
  return true;
}

bool
OracleBackend::getBeforeAndAfterNamesAbsolute(uint32_t zoneId,
  const DNSName& name, DNSName& unhashed, DNSName& before, DNSName& after)
{
  if(!d_dnssecQueries)
    return -1; 

  sword rc;
  OCIStmt *stmt;

  stmt = prepare_query(pooledSvcCtx, prevNextHashQuerySQL, prevNextHashQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_str(stmt, ":hash", mQueryName, sizeof(mQueryName));
  bind_str_ind(stmt, ":unhashed", mResultName, sizeof(mResultName), &mResultNameInd);
  bind_str_ind(stmt, ":prev", mResultPrevName, sizeof(mResultPrevName), &mResultPrevNameInd);
  bind_str_ind(stmt, ":next", mResultNextName, sizeof(mResultNextName), &mResultNextNameInd);
  bind_uint32(stmt, ":zoneid", &zoneId);
  string_to_cbuf(mQueryName, name.labelReverse().toString(" ", false), sizeof(mQueryName));
  mResultNameInd = -1;
  mResultPrevNameInd = -1;
  mResultNextNameInd = -1;

  rc = OCIStmtExecute(pooledSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException(
      "Oracle getBeforeAndAfterNamesAbsolute", oraerr
    );
  }

  check_indicator(mResultNameInd, false);
  check_indicator(mResultPrevNameInd, false);
  check_indicator(mResultNextNameInd, false);

  unhashed = DNSName(mResultName);
  before = DNSName(mResultPrevName);
  after = DNSName(mResultNextName);

  release_query(stmt, prevNextHashQueryKey);
  return true;
}

vector<string>
OracleBackend::getDomainMasters (const DNSName& domain, int zoneId)
{
  sword rc;
  OCIStmt *stmt;

  (void)domain;

  vector<string> masters;
  char master[512];
  sb2 master_ind;

  openMasterConnection();

  stmt = prepare_query(masterSvcCtx, zoneMastersQuerySQL, zoneMastersQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_int(stmt, ":zoneid", &mQueryZoneId);

  mQueryZoneId = zoneId;
  define_output_str(stmt, 1, &master_ind, master, sizeof(master));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle getDomainMasters", oraerr);
  }

  while (rc != OCI_NO_DATA) {
    check_indicator(master_ind, false);

    masters.push_back(master);

    rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);

    if (rc == OCI_ERROR) {
      throw OracleException(
        "OracleBackend, fetching next zone master", oraerr
      );
    }
  }

  release_query(stmt, zoneMastersQueryKey);

  return masters;
}

bool
OracleBackend::getDomainInfo (const DNSName& domain, DomainInfo &di)
{
  sword rc;
  OCIStmt *stmt;

  int zone_id;
  sb2 zone_id_ind;
  int last_check;
  sb2 last_check_ind;
  uint32_t serial;
  sb2 serial_ind;
  uint32_t notified_serial;
  sb2 notified_serial_ind;

  openMasterConnection();

  stmt = prepare_query(masterSvcCtx, zoneInfoQuerySQL, zoneInfoQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  define_output_int(stmt, 1, &zone_id_ind, &zone_id);
  define_output_str(stmt, 2, &mResultNameInd, mResultName, sizeof(mResultName));
  define_output_str(stmt, 3, &mResultTypeInd, mResultType, sizeof(mResultType));
  define_output_int(stmt, 4, &last_check_ind, &last_check);
  define_output_uint32(stmt, 5, &serial_ind, &serial);
  define_output_uint32(stmt, 6, &notified_serial_ind, &notified_serial);

  DNSName_to_cbuf(mQueryZone, domain, sizeof(mQueryZone));
  bind_str(stmt, ":name", mQueryZone, sizeof(mQueryZone));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle getDomainInfo", oraerr);
  }

  if (rc == OCI_NO_DATA) {
    release_query(stmt, zoneInfoQueryKey);
    return false;
  }

  check_indicator(zone_id_ind, false);
  check_indicator(mResultNameInd, false);
  check_indicator(serial_ind, true);

  if (zone_id < 0) throw std::underflow_error("OracleBackend: Zone ID < 0 when writing into uint32_t");

  di.id = zone_id;
  di.zone = DNSName(mResultName);
  di.serial = serial;
  di.backend = this;

  check_indicator(mResultTypeInd, false);
  if (strcasecmp(mResultType, "NATIVE") == 0) {
    di.kind = DomainInfo::Native;
  } else if (strcasecmp(mResultType, "MASTER") == 0) {
    di.kind = DomainInfo::Master;
    check_indicator(notified_serial_ind, false);
    di.notified_serial = notified_serial;
  } else if (strcasecmp(mResultType, "SLAVE") == 0) {
    di.kind = DomainInfo::Slave;
    check_indicator(last_check_ind, true);
    di.last_check = last_check;
    di.masters = getDomainMasters(DNSName(mResultName), zone_id);
  } else {
    throw OracleException("Unknown zone type in Oracle backend");
  }

  di.kind = DomainInfo::Native;

  release_query(stmt, zoneInfoQueryKey);
  return true;
}

void OracleBackend::alsoNotifies(const DNSName& domain, set<string> *addrs)
{
  sword rc;
  OCIStmt *stmt;

  char hostaddr[512];
  sb2 hostaddr_ind;

  openMasterConnection();

  stmt = prepare_query(masterSvcCtx, alsoNotifyQuerySQL, alsoNotifyQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_str(stmt, ":name", mQueryZone, sizeof(mQueryZone));

  DNSName_to_cbuf(mQueryZone, domain, sizeof(mQueryZone));

  define_output_str(stmt, 1, &hostaddr_ind, hostaddr, sizeof(hostaddr));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle alsoNotifies", oraerr);
  }

  while (rc != OCI_NO_DATA) {
    check_indicator(hostaddr_ind, false);

    addrs->insert(hostaddr);

    rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);

    if (rc == OCI_ERROR) {
      throw OracleException(
        "OracleBackend alsoNotifies fetch", oraerr
      );
    }
  }

  release_query(stmt, alsoNotifyQueryKey);
}

void
OracleBackend::getUnfreshSlaveInfos (vector<DomainInfo>* domains)
{
  sword rc;
  OCIStmt *stmt;

  struct timeval now;
  gettimeofday(&now, NULL);
  mQueryTimestamp = now.tv_sec;

  int       last_check;
  sb2       last_check_ind;
  uint32_t  serial;
  sb2       serial_ind;
  char      master[512];
  sb2       master_ind;

  openMasterConnection();

  stmt = prepare_query(masterSvcCtx, unfreshZonesQuerySQL, unfreshZonesQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_int(stmt, ":ts", &mQueryTimestamp);
  define_output_int(stmt, 1, &mResultZoneIdInd, &mResultZoneId);
  define_output_str(stmt, 2, &mResultNameInd, mResultName, sizeof(mResultName));
  define_output_int(stmt, 3, &last_check_ind, &last_check);
  define_output_uint32(stmt, 4, &serial_ind, &serial);
  define_output_str(stmt, 5, &master_ind, master, sizeof(master));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle getUnfreshSlaveInfos", oraerr);
  }

  while (rc != OCI_NO_DATA) {
    check_indicator(mResultZoneIdInd, false);
    check_indicator(mResultNameInd, false);
    check_indicator(serial_ind, true);
    check_indicator(last_check_ind, true);
    int zoneId = mResultZoneId;

    if (mResultZoneId < 0) throw std::underflow_error("OracleBackend: Zone ID < 0 when writing into uint32_t");

    DomainInfo di;
    di.id = mResultZoneId;
    di.zone = DNSName(mResultName);
    di.last_check = last_check;
    di.kind = DomainInfo::Slave;
    di.backend = this;
    if (serial_ind == 0) {
      di.serial = serial;
    }

    while (rc != OCI_NO_DATA && zoneId == mResultZoneId) {
      check_indicator(master_ind, false);
      di.masters.push_back(master);

      rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);

      if (rc == OCI_ERROR) {
        throw OracleException(
          "OracleBackend, fetching next unfresh slave master", oraerr
        );
      }

      check_indicator(mResultZoneIdInd, false);
    }

    domains->push_back(di);
  }

  release_query(stmt, unfreshZonesQueryKey);
}

void
OracleBackend::getUpdatedMasters (vector<DomainInfo>* domains)
{
  sword rc;
  OCIStmt *stmt;

  uint32_t  serial;
  sb2       serial_ind;
  uint32_t  notified_serial;
  sb2       notified_serial_ind;

  openMasterConnection();

  stmt = prepare_query(masterSvcCtx, updatedMastersQuerySQL, updatedMastersQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  define_output_int(stmt, 1, &mResultZoneIdInd, &mResultZoneId);
  define_output_str(stmt, 2, &mResultNameInd, mResultName, sizeof(mResultName));
  define_output_uint32(stmt, 3, &serial_ind, &serial);
  define_output_uint32(stmt, 4, &notified_serial_ind, &notified_serial);

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle getUpdatedMasters", oraerr);
  }

  while (rc != OCI_NO_DATA) {
    check_indicator(mResultZoneIdInd, false);
    check_indicator(mResultNameInd, false);
    check_indicator(serial_ind, false);
    check_indicator(notified_serial_ind, true);

    if (mResultZoneId < 0) throw std::underflow_error("OracleBackend: Zone ID < 0 when writing into uint32_t");

    DomainInfo di;
    di.id = mResultZoneId;
    di.zone = DNSName(mResultName);
    di.serial = serial;
    di.notified_serial = notified_serial;
    di.kind = DomainInfo::Master;
    di.backend = this;

    domains->push_back(di);

    rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);

    if (rc == OCI_ERROR) {
      throw OracleException(
        "OracleBackend, fetching next updated master", oraerr
      );
    }
  }

  release_query(stmt, updatedMastersQueryKey);
}

void
OracleBackend::setFresh (uint32_t zoneId)
{
  sword rc;
  OCIStmt *stmt;

  mQueryZoneId = zoneId;

  struct timeval now;
  gettimeofday(&now, NULL);
  mQueryTimestamp = now.tv_sec;

  openMasterConnection();

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setFresh BEGIN", oraerr);
  }

  stmt = prepare_query(masterSvcCtx, zoneSetLastCheckQuerySQL, zoneSetLastCheckQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_int(stmt, ":zoneid", &mQueryZoneId);
  bind_int(stmt, ":lastcheck", &mQueryTimestamp);

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setFresh", oraerr);
  }

  release_query(stmt, zoneSetLastCheckQueryKey);

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc) {
    throw OracleException("Oracle setFresh COMMIT", oraerr);
  }
}

void
OracleBackend::setNotified (uint32_t zoneId, uint32_t serial)
{
  sword rc;
  OCIStmt *stmt;

  openMasterConnection();

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setNotified BEGIN", oraerr);
  }

  stmt = prepare_query(masterSvcCtx, zoneSetNotifiedSerialQuerySQL, zoneSetNotifiedSerialQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_uint32(stmt, ":serial", &serial);
  bind_uint32(stmt, ":zoneid", &zoneId);

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setNotified", oraerr);
  }

  release_query(stmt, zoneSetNotifiedSerialQueryKey);

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc) {
    throw OracleException("Oracle setNotified COMMIT", oraerr);
  }
}

bool
OracleBackend::list (const DNSName& domain, int zoneId, bool include_disabled)
{
  sword rc;

  // This is only for backends that cannot lookup by zoneId,
  // we can discard
  (void)domain;

  if (curStmtHandle != NULL) throw OracleException("Invalid state");
  curStmtHandle = prepare_query(pooledSvcCtx, listQuerySQL, listQueryKey);
  curStmtKey = listQueryKey;
  define_fwd_query(curStmtHandle);
  bind_str_failokay(curStmtHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(curStmtHandle, ":zoneid", &mQueryZoneId);

  mQueryZoneId = zoneId;

  rc = OCIStmtExecute(pooledSvcCtx, curStmtHandle, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle List", oraerr);
  }

  if (rc == OCI_SUCCESS || rc == OCI_SUCCESS_WITH_INFO) {
    return true;
  }

  if (rc == OCI_NO_DATA) {
    release_query(curStmtHandle, curStmtKey);
    curStmtHandle = NULL;
  }

  return false;
}

bool OracleBackend::get (DNSResourceRecord &rr)
{
  sword rc;

  if (curStmtHandle == NULL) {
    return false;
  }

  check_indicator(mResultNameInd, false);
  check_indicator(mResultTTLInd, false);
  check_indicator(mResultTypeInd, true);
  check_indicator(mResultContentInd, true);
  check_indicator(mResultZoneIdInd, false);
  check_indicator(mResultLastChangeInd, false);
  if (d_dnssecQueries)
    check_indicator(mResultIsAuthInd, false);

  rr.qname = DNSName(mResultName);
  rr.ttl = mResultTTL;
  rr.qtype = mResultType;
  rr.content = mResultContent;
  rr.domain_id = mResultZoneId;
  rr.last_modified = mResultLastChange;
  if (d_dnssecQueries)
    rr.auth = mResultIsAuth > 0;
  else
    rr.auth = 1;

  rc = OCIStmtFetch2(curStmtHandle, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("OracleBackend, fetching next row", oraerr);
  }

  if (rc == OCI_NO_DATA) {
    release_query(curStmtHandle, curStmtKey);
    curStmtHandle = NULL;
  }

  return true;
}

bool
OracleBackend::startTransaction (const DNSName& domain, int zoneId)
{
  sword rc;
  OCIStmt *stmt;

  (void)domain;

  openMasterConnection();

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle startTransaction", oraerr);
  }

  if (zoneId >= 0) {
    if (openTransactionZoneID >= 0) {
      throw OracleException("Attempt to start AXFR during AXFR");
    }

    mQueryZoneId = openTransactionZoneID = zoneId;

    stmt = prepare_query(masterSvcCtx, deleteZoneQuerySQL, deleteZoneQueryKey);
    bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
    bind_int(stmt, ":zoneid", &mQueryZoneId);

    rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

    if (rc == OCI_ERROR) {
      throw OracleException("Oracle startTransaction deleteZone", oraerr);
    }

    release_query(stmt, deleteZoneQueryKey);
  }

  return true;
}

bool
OracleBackend::feedRecord (const DNSResourceRecord &rr, const DNSName ordername)
{
  sword rc;
  OCIStmt *stmt;

  uint32_t ttl;

  stmt = prepare_query(masterSvcCtx, insertRecordQuerySQL, insertRecordQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_int(stmt, ":zoneid", &mQueryZoneId);
  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));
  bind_str(stmt, ":type", mQueryType, sizeof(mQueryType));
  bind_uint32(stmt, ":ttl", &ttl);
  bind_str(stmt, ":content", mQueryContent, sizeof(mQueryContent));

  mQueryZoneId = rr.domain_id;
  DNSName_to_cbuf(mQueryName, rr.qname, sizeof(mQueryName));
  ttl = rr.ttl;
  string_to_cbuf(mQueryType, rr.qtype.getName(), sizeof(mQueryType));
  string_to_cbuf(mQueryContent, rr.content, sizeof(mQueryContent));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle feedRecord", oraerr);
  }

  release_query(stmt, insertRecordQueryKey);

  return true;
}

bool
OracleBackend::commitTransaction ()
{
  sword rc;
  OCIStmt *stmt;

  if (openTransactionZoneID >= 0) {
    stmt = prepare_query(masterSvcCtx, finalizeAXFRQuerySQL, finalizeAXFRQueryKey);
    bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
    bind_int(stmt, ":zoneid", &openTransactionZoneID);

    rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

    if (rc == OCI_ERROR) {
      throw OracleException("Oracle commitTransaction finalizeAXFR", oraerr);
    }

    release_query(stmt, finalizeAXFRQueryKey);

    openTransactionZoneID = -1;
  }

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc) {
    throw OracleException("Oracle commitTransaction", oraerr);
  }

  return true;
}

bool
OracleBackend::abortTransaction ()
{
  sword err;

  err = OCITransRollback(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (err) {
    throw OracleException("Oracle abortTransaction", oraerr);
  }

  return true;
}

bool
OracleBackend::superMasterBackend (const string &ip, const DNSName& domain,
                                   const vector<DNSResourceRecord> &nsset,
                                   string *nameserver, string *account,
                                   DNSBackend **backend)
{
  sword rc;
  OCIStmt *stmt;

  bool result = false;

  (void)domain;

  string_to_cbuf(mQueryAddr, ip, sizeof(mQueryAddr));

  openMasterConnection();

  stmt = prepare_query(masterSvcCtx, acceptSupernotificationQuerySQL, acceptSupernotificationQueryKey);
  define_output_str(stmt, 1, &mResultNameInd, mResultName, sizeof(mResultName));
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_str(stmt, ":ns", mQueryName, sizeof(mQueryName));
  bind_str(stmt, ":ip", mQueryAddr, sizeof(mQueryAddr));

  for (vector<DNSResourceRecord>::const_iterator i=nsset.begin(); i != nsset.end(); ++i) {
    string_to_cbuf(mQueryName, i->content, sizeof(mQueryName));

    rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

    if (rc == OCI_ERROR) {
      throw OracleException("Oracle superMasterBackend", oraerr);
    }

    if (rc != OCI_NO_DATA) {
      *account = mResultName;
      *backend = this;
      result = true;
      break;
    }
  }

  release_query(stmt, acceptSupernotificationQueryKey);

  return result;
}

bool
OracleBackend::createSlaveDomain(const string &ip, const DNSName& domain,
                                 const string &nameserver, const string &account)
{
  sword rc;
  OCIStmt *insertSlaveQueryHandle;
  OCIStmt *insertMasterQueryHandle;

  DNSName_to_cbuf(mQueryZone, domain, sizeof(mQueryZone));

  openMasterConnection();

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle createSlaveDomain BEGIN", oraerr);
  }

  insertSlaveQueryHandle = prepare_query(masterSvcCtx, insertSlaveQuerySQL, insertSlaveQueryKey);
  bind_str_failokay(insertSlaveQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(insertSlaveQueryHandle, ":zoneid", &mQueryZoneId);
  bind_str(insertSlaveQueryHandle, ":zone", mQueryZone, sizeof(mQueryZone));

  insertMasterQueryHandle = prepare_query(masterSvcCtx, insertMasterQuerySQL, insertMasterQueryKey);
  bind_str_failokay(insertMasterQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(insertMasterQueryHandle, ":zoneid", &mQueryZoneId);
  bind_str(insertMasterQueryHandle, ":ip", mQueryAddr, sizeof(mQueryAddr));

  rc = OCIStmtExecute(masterSvcCtx, insertSlaveQueryHandle, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException(
      "Oracle createSlaveDomain insertSlave", oraerr);
  }

  string_to_cbuf(mQueryAddr, ip, sizeof(mQueryAddr));

  rc = OCIStmtExecute(masterSvcCtx, insertMasterQueryHandle, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException(
      "Oracle createSlaveDomain insertMaster", oraerr);
  }

  release_query(insertSlaveQueryHandle, insertSlaveQueryKey);
  release_query(insertMasterQueryHandle, insertMasterQueryKey);

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc) {
    throw OracleException("Oracle createSlaveDomain COMMIT", oraerr);
  }

  return true;
}

bool
OracleBackend::getAllDomainMetadata (const DNSName& name, std::map<string, vector<string> >& meta)
{
  DomainInfo di;
  if (getDomainInfo(name, di) == false) return false;

  sword rc;
  OCIStmt *stmt;

  stmt = prepare_query(pooledSvcCtx, getAllZoneMetadataQuerySQL, getAllZoneMetadataQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));

  define_output_str(stmt, 1, &mResultTypeInd, mResultType, sizeof(mResultType));
  define_output_str(stmt, 2, &mResultContentInd, mResultContent, sizeof(mResultContent));

  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));

  rc = OCIStmtExecute(pooledSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  while (rc != OCI_NO_DATA) {
    if (rc == OCI_ERROR) {
      throw OracleException("Oracle getAllDomainMetadata", oraerr);
    }
    check_indicator(mResultTypeInd, true);
    check_indicator(mResultContentInd, true);

    string kind = mResultType;
    string content = mResultContent;
    if (!isDnssecDomainMetadata(content))
      meta[kind].push_back(content);

    rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);
  }

  release_query(stmt, getAllZoneMetadataQueryKey);
  return true;
}

bool
OracleBackend::getDomainMetadata (const DNSName& name, const string& kind,
                                  vector<string>& meta)
{
  if(!d_dnssecQueries && isDnssecDomainMetadata(kind))
    return -1;
  DomainInfo di;
  if (getDomainInfo(name, di) == false) return false;

  sword rc;
  OCIStmt *stmt;

  stmt = prepare_query(pooledSvcCtx, getZoneMetadataQuerySQL, getZoneMetadataQueryKey);
  bind_str_failokay(stmt, ":nsname", myServerName, sizeof(myServerName));
  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));
  bind_str(stmt, ":kind", mQueryType, sizeof(mQueryType));
  define_output_str(stmt, 1, &mResultContentInd, mResultContent, sizeof(mResultContent));

  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));
  string_to_cbuf(mQueryType, kind, sizeof(mQueryType));

  rc = OCIStmtExecute(pooledSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  while (rc != OCI_NO_DATA) {
    if (rc == OCI_ERROR) {
      throw OracleException("Oracle getDomainMetadata", oraerr);
    }

    check_indicator(mResultContentInd, true);

    string content = mResultContent;
    meta.push_back(content);

    rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);
  }

  release_query(stmt, getZoneMetadataQueryKey);
  return true;
}

bool
OracleBackend::setDomainMetadata(const DNSName& name, const string& kind,
                                 const vector<string>& meta)
{
  if(!d_dnssecQueries && isDnssecDomainMetadata(kind))
    return -1;
  DomainInfo di;
  if (getDomainInfo(name, di) == false) return false;

  sword rc;
  OCIStmt *stmt;

  openMasterConnection();

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setDomainMetadata BEGIN", oraerr);
  }

  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));
  string_to_cbuf(mQueryType, kind, sizeof(mQueryType));

  stmt = prepare_query(masterSvcCtx, delZoneMetadataQuerySQL, delZoneMetadataQueryKey);
  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));
  bind_str(stmt, ":kind", mQueryType, sizeof(mQueryType));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setDomainMetadata DELETE", oraerr);
  }

  release_query(stmt, delZoneMetadataQueryKey);

  stmt = prepare_query(masterSvcCtx, setZoneMetadataQuerySQL, setZoneMetadataQueryKey);

  int i = 0;

  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));
  bind_str(stmt, ":kind", mQueryType, sizeof(mQueryType));
  bind_int(stmt, ":i", &i);
  bind_str(stmt, ":content", mQueryContent, sizeof(mQueryContent));

  for (vector<string>::const_iterator it = meta.begin(); it != meta.end(); ++it) {
    string_to_cbuf(mQueryContent, *it, sizeof(mQueryContent));
    rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);
    if (rc == OCI_ERROR) {
      throw OracleException("Oracle setDomainMetadata INSERT", oraerr);
    }
    i++;
  }

  release_query(stmt, setZoneMetadataQueryKey);

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setDomainMetadata COMMIT", oraerr);
  }

  return true;
}

bool
OracleBackend::getTSIGKey (const DNSName& name, DNSName* algorithm, string* content)
{
  sword rc;
  OCIStmt *stmt;

  stmt = prepare_query(pooledSvcCtx, getTSIGKeyQuerySQL, getTSIGKeyQueryKey);
  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));
  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));

  define_output_str(stmt, 1, &mResultTypeInd, mResultType, sizeof(mResultType));
  define_output_str(stmt, 2, &mResultContentInd, mResultContent, sizeof(mResultContent));

  rc = OCIStmtExecute(pooledSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  content->clear();
  while (rc != OCI_NO_DATA) {

    if (rc == OCI_ERROR) {
      throw OracleException("Oracle getTSIGKey", oraerr);
    }

    check_indicator(mResultTypeInd, false);
    check_indicator(mResultContentInd, false);

    if(algorithm->empty() || *algorithm==DNSName(mResultType)) {
      *algorithm = DNSName(mResultType);
      *content = mResultContent;
    }

    rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);
  }

  release_query(stmt, getTSIGKeyQueryKey);
  return !content->empty();
}

bool
OracleBackend::delTSIGKey(const DNSName& name)
{
  sword rc;
  OCIStmt *stmt;

  openMasterConnection();
  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  stmt = prepare_query(masterSvcCtx, delTSIGKeyQuerySQL, delTSIGKeyQueryKey);
  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));

  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle delTSIGKey", oraerr);
  }

  release_query(stmt, setTSIGKeyQueryKey);

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);
  if (rc == OCI_ERROR) {
    throw OracleException("Oracle delTSIGKey COMMIT", oraerr);
  }
  return true;
}

bool
OracleBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content)
{
  sword rc;
  OCIStmt *stmt;

  openMasterConnection();

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setTSIGKey BEGIN", oraerr);
  }

  stmt = prepare_query(masterSvcCtx, delTSIGKeyQuerySQL, delTSIGKeyQueryKey);
  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));

  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setTSIGKey DELETE", oraerr);
  }

  release_query(stmt, delTSIGKeyQueryKey);

  stmt = prepare_query(masterSvcCtx, setTSIGKeyQuerySQL, setTSIGKeyQueryKey);
  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));
  DNSName_to_cbuf(mQueryType, algorithm, sizeof(mQueryType));
  string_to_cbuf(mQueryContent, content, sizeof(mQueryContent));

  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));
  bind_str(stmt, ":algorithm", mQueryType, sizeof(mQueryType));
  bind_str(stmt, ":secret", mQueryContent, sizeof(mQueryContent));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setTSIGKey INSERT", oraerr);
  }

  release_query(stmt, setTSIGKeyQueryKey);

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setTSIGKey COMMIT", oraerr);
  }

  return true;
}

bool
OracleBackend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{
  sword rc;
  OCIStmt *stmt;

  stmt = prepare_query(pooledSvcCtx, getTSIGKeysQuerySQL, getTSIGKeysQueryKey);
  define_output_str(stmt, 1, &mResultNameInd, mResultName, sizeof(mResultName));
  define_output_str(stmt, 2, &mResultTypeInd, mResultType, sizeof(mResultType));
  define_output_str(stmt, 3, &mResultContentInd, mResultContent, sizeof(mResultContent));

  rc = OCIStmtExecute(pooledSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  while (rc != OCI_NO_DATA) {
    if (rc == OCI_ERROR) {
      throw OracleException("Oracle getDomainMetadata", oraerr);
    }

    check_indicator(mResultNameInd, true);
    check_indicator(mResultTypeInd, true);
    check_indicator(mResultContentInd, true);

    struct TSIGKey key;

    key.name = DNSName(mResultName);
    key.algorithm = DNSName(mResultType);
    key.key = mResultContent;
    keys.push_back(key);

    rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);
  }

  release_query(stmt, getTSIGKeyQueryKey);
  return true;
}

bool
OracleBackend::getDomainKeys (const DNSName& name, vector<KeyData>& keys)
{
  if(!d_dnssecQueries)
    return -1;
  DomainInfo di;
  if (getDomainInfo(name, di) == false) return false;

  sword rc;
  OCIStmt *stmt;

  stmt = prepare_query(pooledSvcCtx, getZoneKeysQuerySQL, getZoneKeysQueryKey);
  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));

  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));

  sb2 key_id_ind = 0;
  unsigned int key_id = 0;
  sb2 key_flags_ind = 0;
  uint16_t key_flags = 0;
  sb2 key_active_ind = 0;
  int key_active = 0;

  define_output_uint(stmt, 1, &key_id_ind, &key_id);
  define_output_uint16(stmt, 2, &key_flags_ind, &key_flags);
  define_output_int(stmt, 3, &key_active_ind, &key_active);
  define_output_str(stmt, 4, &mResultContentInd, mResultContent, sizeof(mResultContent));

  rc = OCIStmtExecute(pooledSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  while (rc != OCI_NO_DATA) {
    if (rc == OCI_ERROR) {
      throw OracleException("Oracle getDomainKeys", oraerr);
    }

    check_indicator(key_id_ind, false);
    check_indicator(key_flags_ind, false);
    check_indicator(key_active_ind, false);
    check_indicator(mResultContentInd, false);

    KeyData kd;
    kd.id = key_id;
    kd.flags = key_flags;
    kd.active = key_active;
    kd.content = mResultContent;
    keys.push_back(kd);

    rc = OCIStmtFetch2(stmt, oraerr, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);
  }

  release_query(stmt, getZoneKeysQueryKey);
  return true;
}

bool
OracleBackend::removeDomainKey (const DNSName& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return -1;
  DomainInfo di;
  if (getDomainInfo(name, di) == false) return false;

  sword rc;
  OCIStmt *stmt;

  openMasterConnection();

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle removeDomainKey BEGIN", oraerr);
  }

  stmt = prepare_query(masterSvcCtx, delZoneKeyQuerySQL, delZoneKeyQueryKey);
  bind_uint(stmt, ":keyid", &id);

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle removeDomainKey DELETE", oraerr);
  }

  release_query(stmt, delZoneKeyQueryKey);

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle removeDomainKey COMMIT", oraerr);
  }

  return true;
}

bool
OracleBackend::addDomainKey (const DNSName& name, const KeyData& key, int64_t& id)
{
  if(!d_dnssecQueries)
    return false;
  DomainInfo di;
  if (getDomainInfo(name, di) == false) return false;

  sword rc;
  OCIStmt *stmt;

  int key_id = -1;
  uint16_t key_flags = key.flags;
  int key_active = key.active;

  openMasterConnection();

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle addDomainKey BEGIN", oraerr);
  }

  DNSName_to_cbuf(mQueryName, name, sizeof(mQueryName));
  string_to_cbuf(mQueryContent, key.content, sizeof(mQueryContent));

  stmt = prepare_query(masterSvcCtx, addZoneKeyQuerySQL, addZoneKeyQueryKey);

  bind_int(stmt, ":keyid", &key_id);
  bind_str(stmt, ":name", mQueryName, sizeof(mQueryName));
  bind_uint16(stmt, ":flags", &key_flags);
  bind_int(stmt, ":active", &key_active);
  bind_str(stmt, ":content", mQueryContent, sizeof(mQueryContent));

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle addDomainKey INSERT", oraerr);
  }

  release_query(stmt, addZoneKeyQueryKey);

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle addDomainKey COMMIT", oraerr);
  }

  id = key_id;
  return key_id >= 0;
}

bool
OracleBackend::setDomainKeyState (const DNSName& name, unsigned int id, int active)
{
  if(!d_dnssecQueries)
    return -1;
  DomainInfo di;
  if (getDomainInfo(name, di) == false) return false;

  sword rc;
  OCIStmt *stmt;

  openMasterConnection();

  stmt = prepare_query(masterSvcCtx, setZoneKeyStateQuerySQL, setZoneKeyStateQueryKey);
  bind_uint(stmt, ":keyid", &id);
  bind_int(stmt, ":active", &active);

  rc = OCITransStart(masterSvcCtx, oraerr, 60, OCI_TRANS_NEW);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setDomainKeyState BEGIN", oraerr);
  }

  rc = OCIStmtExecute(masterSvcCtx, stmt, oraerr, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setDomainKeyState UPDATE", oraerr);
  }

  rc = OCITransCommit(masterSvcCtx, oraerr, OCI_DEFAULT);

  if (rc == OCI_ERROR) {
    throw OracleException("Oracle setDomainKeyState COMMIT", oraerr);
  }

  release_query(stmt, setZoneKeyStateQueryKey);
  return true;
}

bool
OracleBackend::activateDomainKey (const DNSName& name, unsigned int id)
{
  return setDomainKeyState(name, id, 1);
}

bool
OracleBackend::deactivateDomainKey (const DNSName& name, unsigned int id)
{
  return setDomainKeyState(name, id, 0);
}

void
OracleBackend::Cleanup ()
{
  sword err;

  if (masterSvcCtx != NULL) {
    err = OCITransRollback(masterSvcCtx, oraerr, OCI_DEFAULT);
    // No error check, we don't care if ROLLBACK failed
    err = OCISessionRelease(masterSvcCtx, oraerr, NULL, 0, OCI_DEFAULT);
    if (err == OCI_ERROR) {
      throw OracleException("Oracle cleanup, OCISessionRelease (master)", oraerr);
    }
    masterSvcCtx = NULL;
    OCIHandleFree(masterAuthHandle, OCI_HTYPE_AUTHINFO);
    masterAuthHandle = NULL;
  }

  if (pooledSvcCtx != NULL) {
    err = OCITransRollback(pooledSvcCtx, oraerr, OCI_DEFAULT);
    // No error check, we don't care if ROLLBACK failed
    err = OCISessionRelease(pooledSvcCtx, oraerr, NULL, 0, OCI_DEFAULT);
    if (err == OCI_ERROR) {
      throw OracleException("Oracle cleanup, OCISessionRelease (pooled)", oraerr);
    }
    pooledSvcCtx = NULL;
  }

  if (oraerr != NULL) {
    OCIHandleFree(oraerr, OCI_HTYPE_ERROR);
    oraerr = NULL;
  }
}

OCIStmt*
OracleBackend::prepare_query (OCISvcCtx *orasvc, string& code, const char *key)
{
  sword err;

  OCIStmt *handle = NULL;

  err = OCIStmtPrepare2(orasvc, &handle, oraerr, (OraText*) code.c_str(), code.length(), (OraText*) key, strlen(key), OCI_NTV_SYNTAX, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Preparing Oracle statement", oraerr);
  }

  return handle;
}

void
OracleBackend::release_query (OCIStmt *stmt, const char *key)
{
  sword err;

  err = OCIStmtRelease(stmt, oraerr, (OraText*)key, strlen(key), OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Releasing Oracle statement", oraerr);
  }
}

void
OracleBackend::define_output_str (OCIStmt *s, ub4 pos, sb2 *ind,
                                  char *buf, sb4 buflen)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, oraerr, pos, buf, buflen, SQLT_STR,
                       ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", oraerr);
  }
}

void
OracleBackend::define_output_int (OCIStmt *s, ub4 pos, sb2 *ind, int *buf)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, oraerr, pos, buf, sizeof(int),
                       SQLT_INT, ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", oraerr);
  }
}

void
OracleBackend::define_output_uint (OCIStmt *s, ub4 pos, sb2 *ind, unsigned int *buf)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, oraerr, pos, buf, sizeof(unsigned int),
                       SQLT_UIN, ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", oraerr);
  }
}

void
OracleBackend::define_output_uint16 (OCIStmt *s, ub4 pos, sb2 *ind,
                                     uint16_t *buf)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, oraerr, pos, buf, sizeof(uint16_t),
                       SQLT_UIN, ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", oraerr);
  }
}

void
OracleBackend::define_output_uint32 (OCIStmt *s, ub4 pos, sb2 *ind,
                                     uint32_t *buf)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, oraerr, pos, buf, sizeof(uint32_t),
                       SQLT_UIN, ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", oraerr);
  }
}

void
OracleBackend::check_indicator (sb2 ind, bool null_okay)
{
  if ((!null_okay) && (ind == -1)) {
    throw OracleException("Received NULL where a value was expected");
  }

  if ((ind < -1) || (ind > 0)) {
    throw OracleException("Return value truncated");
  }
}

void
OracleBackend::define_fwd_query (OCIStmt *s)
{
  const ub4 n = 100;
  sword err = OCIAttrSet(s, OCI_HTYPE_STMT, (void*) &n, sizeof(ub4),
                         OCI_ATTR_PREFETCH_ROWS, oraerr);

  if (err == OCI_ERROR) {
    throw OracleException("Activating row prefetching", oraerr);
  }

  define_output_str(s, 1, &mResultNameInd,
                    mResultName, sizeof(mResultName));
  define_output_uint32(s, 2, &mResultTTLInd, &mResultTTL);
  define_output_str(s, 3, &mResultTypeInd,
                    mResultType, sizeof(mResultType));
  define_output_str(s, 4, &mResultContentInd,
                    mResultContent, sizeof(mResultContent));
  define_output_int(s, 5, &mResultZoneIdInd, &mResultZoneId);
  define_output_int(s, 6, &mResultLastChangeInd, &mResultLastChange);
  if (d_dnssecQueries)
    define_output_int(s, 7, &mResultIsAuthInd, &mResultIsAuth);
}

void
OracleBackend::bind_str (OCIStmt *s, const char *name, char *buf, sb4 buflen)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, oraerr,
                      (OraText*) name, strlen(name),
                      buf, buflen, SQLT_STR,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    string msg;
    msg.append("Oracle bind_str (\"");
    msg.append(name);
    msg.append("\")");
    throw OracleException(msg, oraerr);
  }
}

void
OracleBackend::bind_str_failokay (OCIStmt *s, const char *name,
                                  char *buf, sb4 buflen)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, oraerr,
                      (OraText*) name, strlen(name),
                      buf, buflen, SQLT_STR,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  (void)err;
}

void
OracleBackend::bind_str_ind (OCIStmt *s, const char *name,
                             char *buf, sb4 buflen, sb2 *ind)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, oraerr,
                      (OraText*) name, strlen(name),
                      buf, buflen, SQLT_STR,
                      ind, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    string msg;
    msg.append("Oracle bind_str_ind (\"");
    msg.append(name);
    msg.append("\")");
    throw OracleException(msg, oraerr);
  }
}

void
OracleBackend::bind_int (OCIStmt *s, const char *name, int *buf)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, oraerr,
                      (OraText*) name, strlen(name),
                      buf, sizeof(int), SQLT_INT,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    string msg;
    msg.append("Oracle bind_int (\"");
    msg.append(name);
    msg.append("\")");
    throw OracleException(msg, oraerr);
  }
}

void
OracleBackend::bind_uint (OCIStmt *s, const char *name, unsigned int *buf)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, oraerr,
                      (OraText*) name, strlen(name),
                      buf, sizeof(unsigned int), SQLT_UIN,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    string msg;
    msg.append("Oracle bind_uint (\"");
    msg.append(name);
    msg.append("\")");
    throw OracleException(msg, oraerr);
  }
}

void
OracleBackend::bind_uint16 (OCIStmt *s, const char *name, uint16_t *buf)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, oraerr,
                      (OraText*) name, strlen(name),
                      buf, sizeof(uint16_t), SQLT_UIN,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    string msg;
    msg.append("Oracle bind_uint16 (\"");
    msg.append(name);
    msg.append("\")");
    throw OracleException(msg, oraerr);
  }
}

void
OracleBackend::bind_uint16_ind (OCIStmt *s, const char *name, uint16_t *buf,
                                sb2 *ind)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, oraerr,
                      (OraText*) name, strlen(name),
                      buf, sizeof(uint16_t), SQLT_UIN,
                      ind, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    string msg;
    msg.append("Oracle bind_uint16_ind (\"");
    msg.append(name);
    msg.append("\")");
    throw OracleException(msg, oraerr);
  }
}

void
OracleBackend::bind_uint32 (OCIStmt *s, const char *name, uint32_t *buf)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, oraerr,
                      (OraText*) name, strlen(name),
                      buf, sizeof(uint32_t), SQLT_UIN,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    string msg;
    msg.append("Oracle bind_uint32 (\"");
    msg.append(name);
    msg.append("\")");
    throw OracleException(msg, oraerr);
  }
}


class OracleFactory : public BackendFactory
{
private:
  pthread_mutex_t factoryLock;
  OCIEnv *oraenv;
  OCIError *oraerr;
  OCISPool *mSessionPoolHandle;
  text *mSessionPoolName;
  ub4 mSessionPoolNameLen;

  void CreateSessionPool ()
  {
    sword err;

    try {
      // set some environment variables
      setenv("ORACLE_HOME", arg()["oracle-home"].c_str(), 1);
      setenv("ORACLE_SID", arg()["oracle-sid"].c_str(), 1);
      setenv("NLS_LANG", arg()["oracle-nls-lang"].c_str(), 1);

      // Initialize and create the environment
      err = OCIEnvCreate(&oraenv, OCI_THREADED, NULL, NULL,
                         NULL, NULL, 0, NULL);
      if (err == OCI_ERROR) {
        throw OracleException("OCIEnvCreate");
      }
      // Allocate an error handle
      err = OCIHandleAlloc(oraenv, (void**) &oraerr,
                           OCI_HTYPE_ERROR, 0, NULL);
      if (err == OCI_ERROR) {
        throw OracleException("OCIHandleAlloc");
      }

      const char *dbname = arg()["oracle-pool-database"].c_str();
      const char *dbuser = arg()["oracle-pool-username"].c_str();
      const char *dbpass = arg()["oracle-pool-password"].c_str();

      ub4 sess_min = arg().asNum("oracle-session-min");
      ub4 sess_max = arg().asNum("oracle-session-max");
      ub4 sess_inc = arg().asNum("oracle-session-inc");
      ub4 get_mode = OCI_SPOOL_ATTRVAL_NOWAIT;

      // Create a session pool
      err = OCIHandleAlloc(oraenv, (void**) &mSessionPoolHandle,
                           OCI_HTYPE_SPOOL, 0, NULL);
      if (err == OCI_ERROR) {
        throw OracleException("OCIHandleAlloc");
      }
      err = OCISessionPoolCreate(oraenv, oraerr,
                                 mSessionPoolHandle,
                                 (OraText **) &mSessionPoolName,
                                 &mSessionPoolNameLen,
                                 (OraText *) dbname, strlen(dbname),
                                 sess_min, sess_max, sess_inc,
                                 (OraText *) dbuser, strlen(dbuser),
                                 (OraText *) dbpass, strlen(dbpass),
                                 OCI_SPC_STMTCACHE | OCI_SPC_HOMOGENEOUS);
      if (err == OCI_ERROR) {
        throw OracleException("Creating Oracle session pool", oraerr);
      }

      // Set session pool NOWAIT
      err = OCIAttrSet(mSessionPoolHandle, OCI_HTYPE_SPOOL, &get_mode, 0, OCI_ATTR_SPOOL_GETMODE, oraerr);
      if (err == OCI_ERROR) {
        throw OracleException("Setting session pool get mode", oraerr);
      }
    } catch (OracleException &theException) {
      g_log << Logger::Critical << "OracleFactory: "
        << theException.reason << endl;
      Cleanup();
      throw theException;
    }
  }

  void Cleanup ()
  {
    sword err;

    if (mSessionPoolHandle != NULL) {
      try {
        err = OCISessionPoolDestroy(mSessionPoolHandle, oraerr,
                                    OCI_SPD_FORCE);
        OCIHandleFree(mSessionPoolHandle, OCI_HTYPE_SPOOL);
        mSessionPoolHandle = NULL;
        if (err == OCI_ERROR) {
          throw OracleException("OCISessionPoolDestroy", oraerr);
        }
      } catch (OracleException &theException) {
        g_log << Logger::Error << "Failed to destroy Oracle session pool: "
          << theException.reason << endl;
      }
    }

    if (oraerr != NULL) {
      OCIHandleFree(oraerr, OCI_HTYPE_ERROR);
      oraerr = NULL;
    }

    if (oraenv != NULL) {
      OCIHandleFree(oraenv, OCI_HTYPE_ENV);
      oraenv = NULL;
    }
  }

public:

OracleFactory () : BackendFactory("oracle") {
    pthread_mutex_init(&factoryLock, NULL);
    oraenv = NULL;
    oraerr = NULL;
    mSessionPoolHandle = NULL;
    mSessionPoolName = NULL;
    mSessionPoolNameLen = 0;
  }

  ~OracleFactory () {
    Cleanup();
    pthread_mutex_destroy(&factoryLock);
  }

  void declareArguments (const string & suffix = "") {
    declare(suffix,"home", "Oracle home path", "");
    declare(suffix,"sid", "Oracle sid", "XE");
    declare(suffix,"nls-lang", "Oracle language", "AMERICAN_AMERICA.AL32UTF8");

    declare(suffix, "pool-database", "Database to connect to for the session pool", "powerdns");
    declare(suffix, "pool-username", "Username to connect as for the session pool", "powerdns");
    declare(suffix, "pool-password", "Password to connect with for the session pool", "");
    declare(suffix, "session-min", "Number of sessions to open at startup", "4");
    declare(suffix, "session-inc", "Number of sessions to open when growing", "2");
    declare(suffix, "session-max", "Max number of sessions to have open", "20");
    declare(suffix, "master-database", "Database to connect to for write access", "powerdns");
    declare(suffix, "master-username", "Username to connect as for write access", "powerdns");
    declare(suffix, "master-password", "Password to connect with for write access", "");
    declare(suffix, "dnssec", "Assume DNSSEC Schema is in place", "no");
    declare(suffix, "nameserver-name", "", "");

    declare(suffix, "basic-query", "", basicQueryDefaultSQL);
    declare(suffix, "basic-query-auth", "", basicQueryDefaultAuthSQL);
    declare(suffix, "basic-id-query", "", basicIdQueryDefaultSQL);
    declare(suffix, "basic-id-query-auth", "", basicIdQueryDefaultAuthSQL);
    declare(suffix, "any-query", "", anyQueryDefaultSQL);
    declare(suffix, "any-query-auth", "", anyQueryDefaultAuthSQL);
    declare(suffix, "any-id-query", "", anyIdQueryDefaultSQL);
    declare(suffix, "any-id-query-auth", "", anyIdQueryDefaultAuthSQL);
    declare(suffix, "list-query", "", listQueryDefaultSQL);
    declare(suffix, "list-query-auth", "", listQueryDefaultAuthSQL);
    declare(suffix, "zone-info-query", "", zoneInfoQueryDefaultSQL);
    declare(suffix, "also-notify-query", "", alsoNotifyQueryDefaultSQL);
    declare(suffix, "zone-masters-query", "", zoneMastersQueryDefaultSQL);
    declare(suffix, "delete-zone-query", "", deleteZoneQueryDefaultSQL);
    declare(suffix, "zone-set-last-check-query", "", zoneSetLastCheckQueryDefaultSQL);
    declare(suffix, "zone-set-notified-serial-query", "", zoneSetNotifiedSerialQueryDefaultSQL);
    declare(suffix, "insert-record-query", "", insertRecordQueryDefaultSQL);
    declare(suffix, "finalize-axfr-query", "", finalizeAXFRQueryDefaultSQL);
    declare(suffix, "unfresh-zones-query", "", unfreshZonesQueryDefaultSQL);
    declare(suffix, "updated-masters-query", "", updatedMastersQueryDefaultSQL);
    declare(suffix, "accept-supernotification-query", "", acceptSupernotificationQueryDefaultSQL);
    declare(suffix, "insert-slave-query", "", insertSlaveQueryDefaultSQL);
    declare(suffix, "insert-master-query", "", insertMasterQueryDefaultSQL);
    declare(suffix, "prev-next-name-query", "", prevNextNameQueryDefaultSQL);
    declare(suffix, "prev-next-hash-query", "", prevNextHashQueryDefaultSQL);

    declare(suffix, "get-all-zone-metadata-query", "", getAllZoneMetadataQueryDefaultSQL);
    declare(suffix, "get-zone-metadata-query", "", getZoneMetadataQueryDefaultSQL);
    declare(suffix, "del-zone-metadata-query", "", delZoneMetadataQueryDefaultSQL);
    declare(suffix, "set-zone-metadata-query", "", setZoneMetadataQueryDefaultSQL);

    declare(suffix, "get-tsig-key-query", "", getTSIGKeyQueryDefaultSQL);
    declare(suffix, "del-tsig-key-query", "", delTSIGKeyQueryDefaultSQL);
    declare(suffix, "set-tsig-key-query", "", setTSIGKeyQueryDefaultSQL);
    declare(suffix, "get-tsig-keys-query", "", getTSIGKeysQueryDefaultSQL);

    declare(suffix, "get-zone-keys-query", "", getZoneKeysQueryDefaultSQL);
    declare(suffix, "del-zone-key-query", "", delZoneKeyQueryDefaultSQL);
    declare(suffix, "add-zone-key-query", "", addZoneKeyQueryDefaultSQL);
    declare(suffix, "set-zone-key-state-query", "", setZoneKeyStateQueryDefaultSQL);
  }

  DNSBackend *make (const string & suffix = "") {
    {
      Lock l(&factoryLock);
      if (oraenv == NULL) {
        CreateSessionPool();
      }
    }
    return new OracleBackend(suffix, oraenv,
                             (char *) mSessionPoolName);
  }

};


//! Magic class that is activated when the dynamic library is loaded
class OracleLoader
{
public:

  OracleLoader()
  {
    BackendMakers().report(new OracleFactory);
    g_log << Logger::Info << "[oraclebackend] This is the oracle backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }

};

static OracleLoader loader;

/* vi: set sw=2 et : */
