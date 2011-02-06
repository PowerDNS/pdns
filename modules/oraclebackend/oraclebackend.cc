// $Id$

/*
 * Copyright (c) 2010-2011
 *
 * Maik Zumstrull <maik@zumstrull.net>
 * Steinbuch Centre for Computing <http://www.scc.kit.edu/>
 * Karlsruhe Institute of Technology <http://www.kit.edu/>
 *
 */

#include <string>

#include "namespaces.hh"

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "oraclebackend.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/lock.hh"

#include <oci.h>

static const char *basicQueryKey = "PDNS_Basic_Query";
static const char *basicQueryDefaultSQL =
  "SELECT fqdn, ttl, type, content, zone_id, last_change, auth "
  "FROM Records "
  "WHERE type = :type AND fqdn = lower(:name)";

static const char *basicIdQueryKey = "PDNS_Basic_Id_Query";
static const char *basicIdQueryDefaultSQL =
  "SELECT fqdn, ttl, type, content, zone_id, last_change, auth "
  "FROM Records "
  "WHERE type = :type AND fqdn = lower(:name) AND zone_id = :zoneid";

static const char *anyQueryKey = "PDNS_ANY_Query";
static const char *anyQueryDefaultSQL =
  "SELECT fqdn, ttl, type, content, zone_id, last_change, auth "
  "FROM Records "
  "WHERE fqdn = lower(:name)";

static const char *anyIdQueryKey = "PDNS_ANY_Id_Query";
static const char *anyIdQueryDefaultSQL =
  "SELECT fqdn, ttl, type, content, zone_id, last_change, auth "
  "FROM Records "
  "WHERE fqdn = lower(:name) AND zone_id = :zoneid";

static const char *listQueryKey = "PDNS_List_Query";
static const char *listQueryDefaultSQL =
  "SELECT fqdn, ttl, type, content, zone_id, last_change, auth "
  "FROM Records "
  "WHERE zone_id = :zoneid";

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

static const char *checkACLQueryKey = "PDNS_Check_ACL_Query";
static const char *checkACLQueryDefaultSQL =
  "BEGIN "
  "  IF EXISTS ( "
  "    SELECT 1 FROM AccessControlList "
  "    WHERE acl_type = :acltype "
  "      AND acl_key = :aclkey "
  "      AND acl_val = :aclval "
  "  ) THEN "
  "    :allow := 1;"
  "  ELSE "
  "    :allow := 0;"
  "  END IF; "
  "END;";

static const char *zoneMastersQueryKey = "PDNS_Zone_Masters_Query";
static const char *zoneMastersQueryDefaultSQL =
  "SELECT master "
  "FROM Zonemasters "
  "WHERE zone_id = :zoneid";

static const char *isZoneMasterQueryKey = "PDNS_Is_Zone_Master_Query";
static const char *isZoneMasterQueryDefaultSQL =
  "SELECT zm.master "
  "FROM Zones z JOIN Zonemasters zm ON z.id = zm.zone_id "
  "WHERE z.name = lower(:name) AND zm.master = :master";

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
  "INSERT INTO Records (fqdn, zone_id, ttl, type, content, last_change) "
  "VALUES (lower(:name), :zoneid, :ttl, :type, :content, :ts)";

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
  if (s.size() > bufsize) {
    throw overflow_error("OracleBackend: string does not fit into char buffer");
  }
  /* Important caveat:
   * If s.size() is exactly bufsize, the char buffer will NOT be
   * zero-terminated. OCI is okay with that, many other functions will not be!
   */
  strncpy(buf, s.c_str(), bufsize);
}

OracleBackend::OracleBackend (const string &suffix, OCIEnv *envh,
                              char *poolname)
{
  setArgPrefix(string("oracle") + suffix);
  sword err;

  // Initialize everything in a known state
  mEnvironmentHandle = envh;
  mErrorHandle = NULL;
  mServiceContextHandle = NULL;
  curStmtHandle = NULL;
  mQueryResult = OCI_ERROR;

  // Process configuration options
  string_to_cbuf(myServerName, getArg("nameserver-name"), sizeof(myServerName));
  basicQuerySQL = getArg("basic-query");
  basicIdQuerySQL = getArg("basic-id-query");
  anyQuerySQL = getArg("any-query");
  anyIdQuerySQL = getArg("any-id-query");
  listQuerySQL = getArg("list-query");
  zoneInfoQuerySQL = getArg("zone-info-query");
  alsoNotifyQuerySQL = getArg("also-notify-query");
  checkACLQuerySQL = getArg("check-acl-query");
  zoneMastersQuerySQL = getArg("zone-masters-query");
  isZoneMasterQuerySQL = getArg("is-zone-master-query");
  deleteZoneQuerySQL = getArg("delete-zone-query");
  zoneSetLastCheckQuerySQL = getArg("zone-set-last-check-query");
  insertRecordQuerySQL = getArg("insert-record-query");
  unfreshZonesQuerySQL = getArg("unfresh-zones-query");
  updatedMastersQuerySQL = getArg("updated-masters-query");
  acceptSupernotificationQuerySQL = getArg("accept-supernotification-query");
  insertSlaveQuerySQL = getArg("insert-slave-query");
  insertMasterQuerySQL = getArg("insert-master-query");
  zoneSetNotifiedSerialQuerySQL = getArg("zone-set-notified-serial-query");
  prevNextNameQuerySQL = getArg("prev-next-name-query");
  prevNextHashQuerySQL = getArg("prev-next-hash-query");
  getZoneMetadataQuerySQL = getArg("get-zone-metadata-query");
  delZoneMetadataQuerySQL = getArg("del-zone-metadata-query");
  setZoneMetadataQuerySQL = getArg("set-zone-metadata-query");
  getZoneKeysQuerySQL = getArg("get-zone-keys-query");
  delZoneKeyQuerySQL = getArg("del-zone-key-query");
  addZoneKeyQuerySQL = getArg("add-zone-key-query");
  setZoneKeyStateQuerySQL = getArg("set-zone-key-state-query");

  // Allocate an error handle
  err = OCIHandleAlloc(mEnvironmentHandle, (void**) &mErrorHandle,
                       OCI_HTYPE_ERROR, 0, NULL);
  if (err == OCI_ERROR) {
    throw OracleException("OCIHandleAlloc");
  }

  // Logon to the database
  err = OCISessionGet(mEnvironmentHandle, mErrorHandle,
                      &mServiceContextHandle, NULL, (OraText*) poolname,
                      strlen(poolname), NULL, 0, NULL, NULL, NULL,
                      OCI_SESSGET_SPOOL);

  if (err == OCI_ERROR) {
    throw OracleException("Opening Oracle session", mErrorHandle);
  }

  // Prepare the statements
  basicQueryHandle = prepare_query(basicQuerySQL, basicQueryKey);
  define_fwd_query(basicQueryHandle);
  bind_str_failokay(basicQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(basicQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_str(basicQueryHandle, ":type", mQueryType, sizeof(mQueryType));

  basicIdQueryHandle = prepare_query(basicIdQuerySQL, basicIdQueryKey);
  define_fwd_query(basicIdQueryHandle);
  bind_str_failokay(basicIdQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(basicIdQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_str(basicIdQueryHandle, ":type", mQueryType, sizeof(mQueryType));
  bind_int(basicIdQueryHandle, ":zoneid", &mQueryZoneId);

  anyQueryHandle = prepare_query(anyQuerySQL, anyQueryKey);
  define_fwd_query(anyQueryHandle);
  bind_str_failokay(anyQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(anyQueryHandle, ":name", mQueryName, sizeof(mQueryName));

  anyIdQueryHandle = prepare_query(anyIdQuerySQL, anyIdQueryKey);
  define_fwd_query(anyIdQueryHandle);
  bind_str_failokay(anyIdQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(anyIdQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_int(anyIdQueryHandle, ":zoneid", &mQueryZoneId);

  listQueryHandle = prepare_query(listQuerySQL, listQueryKey);
  define_fwd_query(listQueryHandle);
  bind_str_failokay(listQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(listQueryHandle, ":zoneid", &mQueryZoneId);

  insertRecordQueryHandle = prepare_query(insertRecordQuerySQL,
                                          insertRecordQueryKey);
  bind_str_failokay(insertRecordQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(insertRecordQueryHandle, ":zoneid", &mQueryZoneId);
  bind_str(insertRecordQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_str(insertRecordQueryHandle, ":type", mQueryType, sizeof(mQueryType));
  bind_int(insertRecordQueryHandle, ":ts", &mQueryTimestamp);

  zoneInfoQueryHandle = prepare_query(zoneInfoQuerySQL, zoneInfoQueryKey);
  bind_str_failokay(zoneInfoQueryHandle, ":nsname", myServerName, sizeof(myServerName));

  unfreshZonesQueryHandle = prepare_query(unfreshZonesQuerySQL,
                                          unfreshZonesQueryKey);
  bind_str_failokay(unfreshZonesQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(unfreshZonesQueryHandle, ":ts", &mQueryTimestamp);

  updatedMastersQueryHandle = prepare_query(updatedMastersQuerySQL,
                                            updatedMastersQueryKey);
  bind_str_failokay(updatedMastersQueryHandle, ":nsname", myServerName, sizeof(myServerName));

  prevNextNameQueryHandle = prepare_query(prevNextNameQuerySQL,
                                          prevNextNameQueryKey);
  bind_str_failokay(prevNextNameQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(prevNextNameQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_str_ind(prevNextNameQueryHandle, ":prev",
               mResultPrevName, sizeof(mResultPrevName), &mResultPrevNameInd);
  bind_str_ind(prevNextNameQueryHandle, ":next",
               mResultNextName, sizeof(mResultNextName), &mResultNextNameInd);

  prevNextHashQueryHandle = prepare_query(prevNextHashQuerySQL,
                                          prevNextHashQueryKey);
  bind_str_failokay(prevNextHashQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(prevNextHashQueryHandle, ":hash", mQueryName, sizeof(mQueryName));
  bind_str_ind(prevNextHashQueryHandle, ":unhashed",
               mResultName, sizeof(mResultName), &mResultNameInd);
  bind_str_ind(prevNextHashQueryHandle, ":prev",
               mResultPrevName, sizeof(mResultPrevName), &mResultPrevNameInd);
  bind_str_ind(prevNextHashQueryHandle, ":next",
               mResultNextName, sizeof(mResultNextName), &mResultNextNameInd);

  getZoneMetadataQueryHandle = prepare_query(getZoneMetadataQuerySQL,
                                             getZoneMetadataQueryKey);
  bind_str_failokay(getZoneMetadataQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(getZoneMetadataQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_str(getZoneMetadataQueryHandle, ":kind", mQueryType, sizeof(mQueryType));
  define_output_str(getZoneMetadataQueryHandle, 1,
                    &mResultContentInd, mResultContent, sizeof(mResultContent));

  getZoneKeysQueryHandle = prepare_query(getZoneKeysQuerySQL, getZoneKeysQueryKey);
  bind_str(getZoneKeysQueryHandle, ":name", mQueryName, sizeof(mQueryName));

  setZoneKeyStateQueryHandle = prepare_query(setZoneKeyStateQuerySQL, setZoneKeyStateQueryKey);
}

OracleBackend::~OracleBackend ()
{
  Cleanup();
}

void
OracleBackend::lookup (const QType &qtype, const string &qname,
                       DNSPacket *p, int zoneId)
{
  if (qtype.getCode() != QType::ANY) {
    if (zoneId < 0) {
      curStmtHandle = basicQueryHandle;
    } else {
      curStmtHandle = basicIdQueryHandle;
    }
  } else {
    if (zoneId < 0) {
      curStmtHandle = anyQueryHandle;
    } else {
      curStmtHandle = anyIdQueryHandle;
    }
  }

  string_to_cbuf(mQueryName, qname, sizeof(mQueryName));
  string_to_cbuf(mQueryType, qtype.getName(), sizeof(mQueryType));
  mQueryZoneId = zoneId;

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, curStmtHandle, mErrorHandle,
                   1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle Lookup", mErrorHandle);
  }
}

bool
OracleBackend::getBeforeAndAfterNames (
  uint32_t zoneId, const string& zone,
  const string& name, string& before, string& after)
{
  (void)zone;

  bind_uint32(prevNextNameQueryHandle, ":zoneid", &zoneId);
  string_to_cbuf(mQueryName, name, sizeof(mQueryName));
  mResultPrevNameInd = -1;
  mResultNextNameInd = -1;

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, prevNextNameQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException(
      "Oracle getBeforeAndAfterNames", mErrorHandle
    );
  }

  check_indicator(mResultPrevNameInd, false);
  check_indicator(mResultNextNameInd, false);

  before = mResultPrevName;
  after = mResultNextName;

  mQueryResult = OCI_ERROR;
  return true;
}

bool
OracleBackend::getBeforeAndAfterNamesAbsolute(uint32_t zoneId,
  const string& name, string& unhashed, string& before, string& after)
{
  bind_uint32(prevNextHashQueryHandle, ":zoneid", &zoneId);
  string_to_cbuf(mQueryName, name, sizeof(mQueryName));
  mResultNameInd = -1;
  mResultPrevNameInd = -1;
  mResultNextNameInd = -1;

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, prevNextHashQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException(
      "Oracle getBeforeAndAfterNamesAbsolute", mErrorHandle
    );
  }

  check_indicator(mResultNameInd, true);
  check_indicator(mResultPrevNameInd, false);
  check_indicator(mResultNextNameInd, false);

  unhashed = mResultName;
  before = mResultPrevName;
  after = mResultNextName;

  mQueryResult = OCI_ERROR;
  return true;
}

vector<string>
OracleBackend::getDomainMasters (const string &domain, int zoneId)
{
  (void)domain;

  vector<string> masters;
  char master[512];
  sb2 master_ind;

  zoneMastersQueryHandle = prepare_query(zoneMastersQuerySQL,
                                         zoneMastersQueryKey);
  bind_str_failokay(zoneMastersQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(zoneMastersQueryHandle, ":zoneid", &mQueryZoneId);

  mQueryZoneId = zoneId;
  define_output_str(zoneMastersQueryHandle, 1, &master_ind,
                    master, sizeof(master));

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, zoneMastersQueryHandle, mErrorHandle,
                   1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle getDomainMasters", mErrorHandle);
  }

  while (mQueryResult != OCI_NO_DATA) {
    check_indicator(master_ind, false);

    masters.push_back(master);

    mQueryResult = OCIStmtFetch2(zoneMastersQueryHandle, mErrorHandle, 1,
                                 OCI_FETCH_NEXT, 0, OCI_DEFAULT);

    if (mQueryResult == OCI_ERROR) {
      throw OracleException(
        "OracleBackend, fetching next zone master", mErrorHandle
      );
    }
  }

  release_query(zoneMastersQueryHandle, zoneMastersQueryKey);

  mQueryResult = OCI_ERROR;
  return masters;
}

bool
OracleBackend::isMaster (const string &domain, const string &master)
{
  isZoneMasterQueryHandle = prepare_query(isZoneMasterQuerySQL,
                                          isZoneMasterQueryKey);

  string_to_cbuf(mQueryZone, domain, sizeof(mQueryZone));
  string_to_cbuf(mQueryName, master, sizeof(mQueryName));

  char res_master[512];
  sb2 res_master_ind;

  bind_str_failokay(isZoneMasterQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(isZoneMasterQueryHandle, ":name", mQueryZone, sizeof(mQueryZone));
  bind_str(isZoneMasterQueryHandle, ":master", mQueryName, sizeof(mQueryName));
  define_output_str(isZoneMasterQueryHandle, 1, &res_master_ind,
                    res_master, sizeof(res_master));

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, isZoneMasterQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle isMaster", mErrorHandle);
  }

  if (mQueryResult != OCI_NO_DATA) {
    check_indicator(res_master_ind, false);
    mQueryResult = OCI_ERROR;
    return true;
  }

  release_query(isZoneMasterQueryHandle, isZoneMasterQueryKey);

  mQueryResult = OCI_ERROR;
  return false;
}

bool
OracleBackend::getDomainInfo (const string &domain, DomainInfo &di)
{
  int zone_id;
  sb2 zone_id_ind;
  int last_check;
  sb2 last_check_ind;
  uint32_t serial;
  sb2 serial_ind;
  uint32_t notified_serial;
  sb2 notified_serial_ind;

  define_output_int(zoneInfoQueryHandle, 1, &zone_id_ind, &zone_id);
  define_output_str(zoneInfoQueryHandle, 2, &mResultNameInd,
                    mResultName, sizeof(mResultName));
  define_output_str(zoneInfoQueryHandle, 3, &mResultTypeInd,
                    mResultType, sizeof(mResultType));
  define_output_int(zoneInfoQueryHandle, 4, &last_check_ind, &last_check);
  define_output_uint32(zoneInfoQueryHandle, 5, &serial_ind, &serial);
  define_output_uint32(zoneInfoQueryHandle, 6, &notified_serial_ind,
                       &notified_serial);

  string_to_cbuf(mQueryZone, domain, sizeof(mQueryZone));
  bind_str(zoneInfoQueryHandle, ":name", mQueryZone, sizeof(mQueryZone));

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, zoneInfoQueryHandle, mErrorHandle,
                   1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle getDomainInfo", mErrorHandle);
  }

  if (mQueryResult == OCI_NO_DATA) {
    return false;
  }

  check_indicator(zone_id_ind, false);
  check_indicator(mResultNameInd, false);
  check_indicator(serial_ind, true);

  if (zone_id < 0) throw underflow_error("OracleBackend: Zone ID < 0 when writing into uint32_t");

  di.id = zone_id;
  di.zone = mResultName;
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
    di.masters = getDomainMasters(mResultName, zone_id);
  } else {
    throw OracleException("Unknown zone type in Oracle backend");
  }


  di.kind = DomainInfo::Native;

  mQueryResult = OCI_ERROR;
  return true;
}

void OracleBackend::alsoNotifies(const string &domain, set<string> *addrs)
{
  char hostaddr[512];
  sb2 hostaddr_ind;

  alsoNotifyQueryHandle = prepare_query(alsoNotifyQuerySQL,
                                        alsoNotifyQueryKey);
  bind_str_failokay(alsoNotifyQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(alsoNotifyQueryHandle, ":name", mQueryZone, sizeof(mQueryZone));

  string_to_cbuf(mQueryZone, domain, sizeof(mQueryZone));

  define_output_str(alsoNotifyQueryHandle, 1, &hostaddr_ind, hostaddr, sizeof(hostaddr));

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, alsoNotifyQueryHandle, mErrorHandle,
                   1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle alsoNotifies", mErrorHandle);
  }

  while (mQueryResult != OCI_NO_DATA) {
    check_indicator(hostaddr_ind, false);

    addrs->insert(hostaddr);

    mQueryResult = OCIStmtFetch2(alsoNotifyQueryHandle, mErrorHandle, 1,
                                 OCI_FETCH_NEXT, 0, OCI_DEFAULT);

    if (mQueryResult == OCI_ERROR) {
      throw OracleException(
        "OracleBackend alsoNotifies fetch", mErrorHandle
      );
    }
  }

  release_query(alsoNotifyQueryHandle, alsoNotifyQueryKey);

  mQueryResult = OCI_ERROR;
}

bool OracleBackend::checkACL (const string &acl_type,
                              const string &acl_key,
                              const string &acl_val)
{
  char acltype[64];
  char aclkey[256];
  char aclval[2048];
  int result = 0;

  checkACLQueryHandle = prepare_query(checkACLQuerySQL, checkACLQueryKey);

  string_to_cbuf(acltype, acl_type, sizeof(acltype));
  string_to_cbuf(aclkey, acl_key, sizeof(aclkey));
  string_to_cbuf(aclval, acl_val, sizeof(aclval));

  bind_str_failokay(checkACLQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(checkACLQueryHandle, ":acltype", acltype, sizeof(acltype));
  bind_str(checkACLQueryHandle, ":aclkey", aclkey, sizeof(aclkey));
  bind_str(checkACLQueryHandle, ":aclval", aclval, sizeof(aclval));
  bind_int(checkACLQueryHandle, ":allow", &result);

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, checkACLQueryHandle, mErrorHandle,
                   1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle checkACL", mErrorHandle);
  }

  release_query(checkACLQueryHandle, checkACLQueryKey);

  return result;
}

void
OracleBackend::getUnfreshSlaveInfos (vector<DomainInfo>* domains)
{
  struct timeval now;
  gettimeofday(&now, NULL);
  mQueryTimestamp = now.tv_sec;

  int       last_check;
  sb2       last_check_ind;
  uint32_t  serial;
  sb2       serial_ind;
  char      master[512];
  sb2       master_ind;

  define_output_int(unfreshZonesQueryHandle, 1,
                    &mResultZoneIdInd, &mResultZoneId);
  define_output_str(unfreshZonesQueryHandle, 2,
                    &mResultNameInd, mResultName, sizeof(mResultName));
  define_output_int(unfreshZonesQueryHandle, 3,
                    &last_check_ind, &last_check);
  define_output_uint32(unfreshZonesQueryHandle, 4,
                       &serial_ind, &serial);
  define_output_str(unfreshZonesQueryHandle, 5,
                    &master_ind, master, sizeof(master));

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, unfreshZonesQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle getUnfreshSlaveInfos", mErrorHandle);
  }

  while (mQueryResult != OCI_NO_DATA) {
    check_indicator(mResultZoneIdInd, false);
    check_indicator(mResultNameInd, false);
    check_indicator(serial_ind, false);
    check_indicator(last_check_ind, true);
    int zoneId = mResultZoneId;

    if (mResultZoneId < 0) throw underflow_error("OracleBackend: Zone ID < 0 when writing into uint32_t");

    DomainInfo di;
    di.id = mResultZoneId;
    di.zone = mResultName;
    di.serial = serial;
    di.last_check = last_check;
    di.kind = DomainInfo::Slave;
    di.backend = this;

    while (mQueryResult != OCI_NO_DATA && zoneId == mResultZoneId) {
      check_indicator(master_ind, false);
      di.masters.push_back(master);

      mQueryResult = OCIStmtFetch2(unfreshZonesQueryHandle, mErrorHandle, 1,
                                   OCI_FETCH_NEXT, 0, OCI_DEFAULT);

      if (mQueryResult == OCI_ERROR) {
        throw OracleException(
          "OracleBackend, fetching next unfresh slave master", mErrorHandle
        );
      }

      check_indicator(mResultZoneIdInd, false);
    }

    domains->push_back(di);
  }

  mQueryResult = OCI_ERROR;
}

void
OracleBackend::getUpdatedMasters (vector<DomainInfo>* domains)
{
  uint32_t  serial;
  sb2       serial_ind;
  uint32_t  notified_serial;
  sb2       notified_serial_ind;

  define_output_int(updatedMastersQueryHandle, 1,
                    &mResultZoneIdInd, &mResultZoneId);
  define_output_str(updatedMastersQueryHandle, 2,
                    &mResultNameInd, mResultName, sizeof(mResultName));
  define_output_uint32(updatedMastersQueryHandle, 3,
                       &serial_ind, &serial);
  define_output_uint32(updatedMastersQueryHandle, 4,
                       &notified_serial_ind, &notified_serial);

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, updatedMastersQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle getUpdatedMasters", mErrorHandle);
  }

  while (mQueryResult != OCI_NO_DATA) {
    check_indicator(mResultZoneIdInd, false);
    check_indicator(mResultNameInd, false);
    check_indicator(serial_ind, false);
    check_indicator(notified_serial_ind, true);

    if (mResultZoneId < 0) throw underflow_error("OracleBackend: Zone ID < 0 when writing into uint32_t");

    DomainInfo di;
    di.id = mResultZoneId;
    di.zone = mResultName;
    di.serial = serial;
    di.notified_serial = notified_serial;
    di.kind = DomainInfo::Master;
    di.backend = this;

    domains->push_back(di);

    mQueryResult = OCIStmtFetch2(updatedMastersQueryHandle, mErrorHandle, 1,
                                 OCI_FETCH_NEXT, 0, OCI_DEFAULT);

    if (mQueryResult == OCI_ERROR) {
      throw OracleException(
        "OracleBackend, fetching next updated master", mErrorHandle
      );
    }
  }

  mQueryResult = OCI_ERROR;
}

void
OracleBackend::setFresh (uint32_t zoneId)
{
  mQueryZoneId = zoneId;

  struct timeval now;
  gettimeofday(&now, NULL);
  mQueryTimestamp = now.tv_sec;

  mQueryResult =
    OCITransStart(mServiceContextHandle, mErrorHandle, 60, OCI_TRANS_NEW);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setFresh BEGIN", mErrorHandle);
  }

  zoneSetLastCheckQueryHandle = prepare_query(zoneSetLastCheckQuerySQL,
                                              zoneSetLastCheckQueryKey);
  bind_str_failokay(zoneSetLastCheckQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(zoneSetLastCheckQueryHandle, ":zoneid", &mQueryZoneId);
  bind_int(zoneSetLastCheckQueryHandle, ":lastcheck", &mQueryTimestamp);

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, zoneSetLastCheckQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setFresh", mErrorHandle);
  }

  release_query(zoneSetLastCheckQueryHandle, zoneSetLastCheckQueryKey);

  mQueryResult =
    OCITransCommit(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (mQueryResult) {
    throw OracleException("Oracle setFresh COMMIT", mErrorHandle);
  }

  mQueryResult = OCI_ERROR;
}

void
OracleBackend::setNotified (uint32_t zoneId, uint32_t serial)
{
  mQueryResult =
    OCITransStart(mServiceContextHandle, mErrorHandle, 60, OCI_TRANS_NEW);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setNotified BEGIN", mErrorHandle);
  }

  zoneSetNotifiedSerialQueryHandle = prepare_query(
    zoneSetNotifiedSerialQuerySQL, zoneSetNotifiedSerialQueryKey);

  bind_str_failokay(zoneSetNotifiedSerialQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_uint32(zoneSetNotifiedSerialQueryHandle, ":serial", &serial);
  bind_uint32(zoneSetNotifiedSerialQueryHandle, ":zoneid", &zoneId);

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, zoneSetNotifiedSerialQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setNotified", mErrorHandle);
  }

  release_query(zoneSetNotifiedSerialQueryHandle, zoneSetNotifiedSerialQueryKey);

  mQueryResult =
    OCITransCommit(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (mQueryResult) {
    throw OracleException("Oracle setNotified COMMIT", mErrorHandle);
  }

  mQueryResult = OCI_ERROR;
}

bool
OracleBackend::list (const string &domain, int zoneId)
{
  // This is only for backends that cannot lookup by zoneId,
  // we can discard
  (void)domain;

  curStmtHandle = listQueryHandle;

  mQueryZoneId = zoneId;

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, curStmtHandle, mErrorHandle,
                   1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle List", mErrorHandle);
  }

  if (mQueryResult == OCI_SUCCESS || mQueryResult == OCI_SUCCESS_WITH_INFO) {
    return true;
  }

  return false;
}

bool OracleBackend::get (DNSResourceRecord &rr)
{
  if (mQueryResult == OCI_NO_DATA || mQueryResult == OCI_ERROR) {
    return false;
  }

  check_indicator(mResultNameInd, false);
  check_indicator(mResultTTLInd, false);
  check_indicator(mResultTypeInd, false);
  check_indicator(mResultContentInd, false);
  check_indicator(mResultZoneIdInd, false);
  check_indicator(mResultLastChangeInd, false);
  check_indicator(mResultIsAuthInd, false);

  rr.qname = mResultName;
  rr.ttl = mResultTTL;
  rr.qtype = mResultType;
  rr.domain_id = mResultZoneId;
  rr.last_modified = mResultLastChange;
  rr.auth = mResultIsAuth > 0;

  if ((rr.qtype.getCode() == QType::MX) || (rr.qtype.getCode() == QType::SRV)) {
    unsigned priority = 0;
    int skip = 0;
    sscanf(mResultContent, "%u %n", &priority, &skip);
    rr.priority = priority;
    rr.content = mResultContent + skip;
  } else {
    rr.content = mResultContent;
  }

  mQueryResult = OCIStmtFetch2(curStmtHandle, mErrorHandle, 1, OCI_FETCH_NEXT,
                               0, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("OracleBackend, fetching next row", mErrorHandle);
  }

  return true;
}

bool
OracleBackend::startTransaction (const string &domain, int zoneId)
{
  (void)domain;

  mQueryResult = OCITransStart(mServiceContextHandle, mErrorHandle, 60, OCI_TRANS_NEW);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle startTransaction", mErrorHandle);
  }

  if (zoneId >= 0) {
    mQueryZoneId = zoneId;

    deleteZoneQueryHandle = prepare_query(deleteZoneQuerySQL,
                                          deleteZoneQueryKey);
    bind_str_failokay(deleteZoneQueryHandle, ":nsname", myServerName, sizeof(myServerName));
    bind_int(deleteZoneQueryHandle, ":zoneid", &mQueryZoneId);

    mQueryResult =
      OCIStmtExecute(mServiceContextHandle, deleteZoneQueryHandle, mErrorHandle,
                     1, 0, NULL, NULL, OCI_DEFAULT);

    if (mQueryResult == OCI_ERROR) {
      throw OracleException("Oracle startTransaction deleteZone", mErrorHandle);
    }

    release_query(deleteZoneQueryHandle, deleteZoneQueryKey);
  }

  mQueryResult = OCI_ERROR;
  return true;
}

bool
OracleBackend::feedRecord (const DNSResourceRecord &rr)
{
  uint32_t ttl;
  char content[4000];

  struct timeval now;
  gettimeofday(&now, NULL);
  mQueryTimestamp = now.tv_sec;

  bind_uint32(insertRecordQueryHandle, ":ttl", &ttl);
  bind_str(insertRecordQueryHandle, ":content", content, sizeof(content));

  mQueryZoneId = rr.domain_id;
  string_to_cbuf(mQueryName, rr.qname, sizeof(mQueryName));
  ttl = rr.ttl;
  string_to_cbuf(mQueryType, rr.qtype.getName(), sizeof(mQueryType));
  if (rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV) {
    snprintf(content, sizeof(content), "%d %s", rr.priority, rr.content.c_str());
  } else {
    string_to_cbuf(content, rr.content, sizeof(content));
  }

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, insertRecordQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle feedRecord", mErrorHandle);
  }

  mQueryResult = OCI_ERROR;
  return true;
}

bool
OracleBackend::commitTransaction ()
{
  sword err;

  err = OCITransCommit(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (err) {
    throw OracleException("Oracle commitTransaction", mErrorHandle);
  }

  mQueryResult = OCI_ERROR;
  return true;
}

bool
OracleBackend::abortTransaction ()
{
  sword err;

  err = OCITransRollback(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (err) {
    throw OracleException("Oracle abortTransaction", mErrorHandle);
  }

  mQueryResult = OCI_ERROR;
  return true;
}

bool
OracleBackend::superMasterBackend (const string &ip, const string &domain,
                                   const vector<DNSResourceRecord> &nsset,
                                   string *account, DNSBackend **backend)
{
  (void)domain;

  string_to_cbuf(mQueryAddr, ip, sizeof(mQueryAddr));

  acceptSupernotificationQueryHandle = prepare_query(
    acceptSupernotificationQuerySQL, acceptSupernotificationQueryKey);
  define_output_str(acceptSupernotificationQueryHandle, 1,
                    &mResultNameInd, mResultName, sizeof(mResultName));
  bind_str_failokay(acceptSupernotificationQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_str(acceptSupernotificationQueryHandle, ":ns",
           mQueryName, sizeof(mQueryName));
  bind_str(acceptSupernotificationQueryHandle, ":ip",
           mQueryAddr, sizeof(mQueryAddr));

  for (vector<DNSResourceRecord>::const_iterator i=nsset.begin();
       i != nsset.end(); ++i) {
    string_to_cbuf(mQueryName, i->content, sizeof(mQueryName));

    mQueryResult =
      OCIStmtExecute(mServiceContextHandle, acceptSupernotificationQueryHandle,
                     mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

    if (mQueryResult == OCI_ERROR) {
      throw OracleException("Oracle superMasterBackend", mErrorHandle);
    }

    if (mQueryResult != OCI_NO_DATA) {
      *account = mResultName;
      *backend = this;
      mQueryResult = OCI_ERROR;
      return true;
    }
  }

  release_query(acceptSupernotificationQueryHandle, acceptSupernotificationQueryKey);

  mQueryResult = OCI_ERROR;
  return false;
}

bool
OracleBackend::createSlaveDomain(const string &ip, const string &domain,
                                 const string &account)
{
  string_to_cbuf(mQueryZone, domain, sizeof(mQueryZone));

  mQueryResult =
    OCITransStart(mServiceContextHandle, mErrorHandle, 60, OCI_TRANS_NEW);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle createSlaveDomain BEGIN", mErrorHandle);
  }

  insertSlaveQueryHandle = prepare_query(insertSlaveQuerySQL,
                                         insertSlaveQueryKey);
  bind_str_failokay(insertSlaveQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(insertSlaveQueryHandle, ":zoneid", &mQueryZoneId);
  bind_str(insertSlaveQueryHandle, ":zone",
           mQueryZone, sizeof(mQueryZone));

  insertMasterQueryHandle = prepare_query(insertMasterQuerySQL,
                                          insertMasterQueryKey);
  bind_str_failokay(insertMasterQueryHandle, ":nsname", myServerName, sizeof(myServerName));
  bind_int(insertMasterQueryHandle, ":zoneid", &mQueryZoneId);
  bind_str(insertMasterQueryHandle, ":ip",
           mQueryAddr, sizeof(mQueryAddr));

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, insertSlaveQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException(
      "Oracle createSlaveDomain insertSlave", mErrorHandle);
  }

  string_to_cbuf(mQueryAddr, ip, sizeof(mQueryAddr));

  mQueryResult =
    OCIStmtExecute(mServiceContextHandle, insertMasterQueryHandle,
                   mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException(
      "Oracle createSlaveDomain insertMaster", mErrorHandle);
  }

  release_query(insertSlaveQueryHandle, insertSlaveQueryKey);
  release_query(insertMasterQueryHandle, insertMasterQueryKey);

  mQueryResult =
    OCITransCommit(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (mQueryResult) {
    throw OracleException("Oracle createSlaveDomain COMMIT", mErrorHandle);
  }

  mQueryResult = OCI_ERROR;
  return true;
}

bool
OracleBackend::getDomainMetadata (const string& name, const string& kind,
                                  vector<string>& meta)
{
  string_to_cbuf(mQueryName, name, sizeof(mQueryName));
  string_to_cbuf(mQueryType, kind, sizeof(mQueryType));

  mQueryResult = OCIStmtExecute(mServiceContextHandle, getZoneMetadataQueryHandle,
                                mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  while (mQueryResult != OCI_NO_DATA) {
    if (mQueryResult == OCI_ERROR) {
      throw OracleException("Oracle getDomainMetadata", mErrorHandle);
    }

    check_indicator(mResultContentInd, true);

    string content = mResultContent;
    meta.push_back(content);

    mQueryResult = OCIStmtFetch2(getZoneMetadataQueryHandle, mErrorHandle, 1, OCI_FETCH_NEXT,
        0, OCI_DEFAULT);
  }

  return true;
}

bool
OracleBackend::setDomainMetadata(const string& name, const string& kind,
                                 const vector<string>& meta)
{
  mQueryResult = OCITransStart(mServiceContextHandle, mErrorHandle, 60, OCI_TRANS_NEW);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setDomainMetadata BEGIN", mErrorHandle);
  }

  string_to_cbuf(mQueryName, name, sizeof(mQueryName));
  string_to_cbuf(mQueryType, kind, sizeof(mQueryType));

  delZoneMetadataQueryHandle = prepare_query(delZoneMetadataQuerySQL,
                                             delZoneMetadataQueryKey);
  bind_str(delZoneMetadataQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_str(delZoneMetadataQueryHandle, ":kind", mQueryType, sizeof(mQueryType));

  mQueryResult = OCIStmtExecute(mServiceContextHandle, delZoneMetadataQueryHandle,
                                mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setDomainMetadata DELETE", mErrorHandle);
  }

  setZoneMetadataQueryHandle = prepare_query(setZoneMetadataQuerySQL,
                                             setZoneMetadataQueryKey);

  int i = 0;

  bind_str(setZoneMetadataQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_str(setZoneMetadataQueryHandle, ":kind", mQueryType, sizeof(mQueryType));
  bind_int(setZoneMetadataQueryHandle, ":i", &i);
  bind_str(setZoneMetadataQueryHandle, ":content", mQueryContent, sizeof(mQueryContent));

  for (vector<string>::const_iterator it = meta.begin(); it != meta.end(); ++it) {
    string_to_cbuf(mQueryContent, *it, sizeof(mQueryContent));
    mQueryResult = OCIStmtExecute(mServiceContextHandle, setZoneMetadataQueryHandle,
        mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);
    if (mQueryResult == OCI_ERROR) {
      throw OracleException("Oracle setDomainMetadata INSERT", mErrorHandle);
    }
    i++;
  }

  release_query(delZoneMetadataQueryHandle, delZoneMetadataQueryKey);
  release_query(setZoneMetadataQueryHandle, setZoneMetadataQueryKey);

  mQueryResult = OCITransCommit(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setDomainMetadata COMMIT", mErrorHandle);
  }

  return true;
}

bool
OracleBackend::getDomainKeys (const string& name, unsigned int kind, vector<KeyData>& keys)
{
  string_to_cbuf(mQueryName, name, sizeof(mQueryName));

  sb2 key_id_ind = 0;
  unsigned int key_id = 0;
  sb2 key_flags_ind = 0;
  uint16_t key_flags = 0;
  sb2 key_active_ind = 0;
  int key_active = 0;
  define_output_uint(getZoneKeysQueryHandle, 1, &key_id_ind, &key_id);
  define_output_uint16(getZoneKeysQueryHandle, 2, &key_flags_ind, &key_flags);
  define_output_int(getZoneKeysQueryHandle, 3, &key_active_ind, &key_active);
  define_output_str(getZoneKeysQueryHandle, 4, &mResultContentInd, mResultContent, sizeof(mResultContent));

  mQueryResult = OCIStmtExecute(mServiceContextHandle, getZoneKeysQueryHandle,
                                mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  while (mQueryResult != OCI_NO_DATA) {
    if (mQueryResult == OCI_ERROR) {
      throw OracleException("Oracle getDomainKeys", mErrorHandle);
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

    mQueryResult = OCIStmtFetch2(getZoneKeysQueryHandle, mErrorHandle, 1, OCI_FETCH_NEXT,
        0, OCI_DEFAULT);
  }

  return true;
}

bool
OracleBackend::removeDomainKey (const string& name, unsigned int id)
{
  mQueryResult = OCITransStart(mServiceContextHandle, mErrorHandle, 60, OCI_TRANS_NEW);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle removeDomainKey BEGIN", mErrorHandle);
  }

  delZoneKeyQueryHandle = prepare_query(delZoneKeyQuerySQL, delZoneKeyQueryKey);
  bind_uint(delZoneKeyQueryHandle, ":keyid", &id);

  mQueryResult = OCIStmtExecute(mServiceContextHandle, delZoneKeyQueryHandle,
                                mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle removeDomainKey DELETE", mErrorHandle);
  }

  release_query(delZoneKeyQueryHandle, delZoneKeyQueryKey);

  mQueryResult = OCITransCommit(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle removeDomainKey COMMIT", mErrorHandle);
  }

  return true;
}

int
OracleBackend::addDomainKey (const string& name, const KeyData& key)
{
  int key_id = -1;
  uint16_t key_flags = key.flags;
  int key_active = key.active;

  mQueryResult = OCITransStart(mServiceContextHandle, mErrorHandle, 60, OCI_TRANS_NEW);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle addDomainKey BEGIN", mErrorHandle);
  }

  string_to_cbuf(mQueryName, name, sizeof(mQueryName));
  string_to_cbuf(mQueryContent, key.content, sizeof(mQueryContent));

  addZoneKeyQueryHandle = prepare_query(addZoneKeyQuerySQL, addZoneKeyQueryKey);

  bind_int(addZoneKeyQueryHandle, ":keyid", &key_id);
  bind_str(addZoneKeyQueryHandle, ":name", mQueryName, sizeof(mQueryName));
  bind_uint16(addZoneKeyQueryHandle, ":flags", &key_flags);
  bind_int(addZoneKeyQueryHandle, ":active", &key_active);
  bind_str(addZoneKeyQueryHandle, ":content", mQueryContent, sizeof(mQueryContent));

  mQueryResult = OCIStmtExecute(mServiceContextHandle, addZoneKeyQueryHandle,
                                mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle addDomainKey INSERT", mErrorHandle);
  }

  release_query(addZoneKeyQueryHandle, addZoneKeyQueryKey);

  mQueryResult = OCITransCommit(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle addDomainKey COMMIT", mErrorHandle);
  }

  return key_id;
}

bool
OracleBackend::setDomainKeyState (const string& name, unsigned int id, int active)
{
  bind_uint(setZoneKeyStateQueryHandle, ":keyid", &id);
  bind_int(setZoneKeyStateQueryHandle, ":active", &active);

  mQueryResult = OCITransStart(mServiceContextHandle, mErrorHandle, 60, OCI_TRANS_NEW);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setDomainKeyState BEGIN", mErrorHandle);
  }

  mQueryResult = OCIStmtExecute(mServiceContextHandle, setZoneKeyStateQueryHandle,
                                mErrorHandle, 1, 0, NULL, NULL, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setDomainKeyState UPDATE", mErrorHandle);
  }

  mQueryResult = OCITransCommit(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);

  if (mQueryResult == OCI_ERROR) {
    throw OracleException("Oracle setDomainKeyState COMMIT", mErrorHandle);
  }

  return true;
}

bool
OracleBackend::activateDomainKey (const string& name, unsigned int id)
{
  return setDomainKeyState(name, id, 1);
}

bool
OracleBackend::deactivateDomainKey (const string& name, unsigned int id)
{
  return setDomainKeyState(name, id, 0);
}

void
OracleBackend::Cleanup ()
{
  sword err;

  if (mServiceContextHandle != NULL) {
    err = OCITransRollback(mServiceContextHandle, mErrorHandle, OCI_DEFAULT);
    // No error check, we don't care if ROLLBACK failed
    err = OCISessionRelease(mServiceContextHandle, mErrorHandle,
                            NULL, 0, OCI_DEFAULT);
    if (err == OCI_ERROR) {
      throw OracleException("Oracle cleanup, OCISessionRelease", mErrorHandle);
    }
    mServiceContextHandle = NULL;
  }

  if (mErrorHandle != NULL) {
    OCIHandleFree(mErrorHandle, OCI_HTYPE_ERROR);
    mErrorHandle = NULL;
  }
}

OCIStmt*
OracleBackend::prepare_query (string& code, const char *key)
{
  sword err;

  OCIStmt *handle = NULL;

  err = OCIStmtPrepare2(mServiceContextHandle, &handle, mErrorHandle,
                        (OraText*) code.c_str(), code.length(),
                        (OraText*) key, strlen(key),
                        OCI_NTV_SYNTAX, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Preparing Oracle statement", mErrorHandle);
  }

  return handle;
}

void
OracleBackend::release_query (OCIStmt *stmt, const char *key)
{
  sword err;

  err = OCIStmtRelease(stmt, mErrorHandle, (OraText*)key, strlen(key), OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Releasing Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::define_output_str (OCIStmt *s, ub4 pos, sb2 *ind,
                                  char *buf, sb4 buflen)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, mErrorHandle, pos, buf, buflen, SQLT_STR,
                       ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::define_output_int (OCIStmt *s, ub4 pos, sb2 *ind, int *buf)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, mErrorHandle, pos, buf, sizeof(int),
                       SQLT_INT, ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::define_output_uint (OCIStmt *s, ub4 pos, sb2 *ind, unsigned int *buf)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, mErrorHandle, pos, buf, sizeof(unsigned int),
                       SQLT_UIN, ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::define_output_uint16 (OCIStmt *s, ub4 pos, sb2 *ind,
                                     uint16_t *buf)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, mErrorHandle, pos, buf, sizeof(uint16_t),
                       SQLT_UIN, ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::define_output_uint32 (OCIStmt *s, ub4 pos, sb2 *ind,
                                     uint32_t *buf)
{
  sword err;
  OCIDefine *handle = NULL;

  err = OCIDefineByPos(s, &handle, mErrorHandle, pos, buf, sizeof(uint32_t),
                       SQLT_UIN, ind, NULL, NULL, OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Defining output for Oracle statement", mErrorHandle);
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
                         OCI_ATTR_PREFETCH_ROWS, mErrorHandle);

  if (err == OCI_ERROR) {
    throw OracleException("Activating row prefetching", mErrorHandle);
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
  define_output_int(s, 7, &mResultIsAuthInd, &mResultIsAuth);
}

void
OracleBackend::bind_str (OCIStmt *s, const char *name, char *buf, sb4 buflen)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, mErrorHandle,
                      (OraText*) name, strlen(name),
                      buf, buflen, SQLT_STR,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Binding input for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::bind_str_failokay (OCIStmt *s, const char *name,
                                  char *buf, sb4 buflen)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, mErrorHandle,
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

  err = OCIBindByName(s, &handle, mErrorHandle,
                      (OraText*) name, strlen(name),
                      buf, buflen, SQLT_STR,
                      ind, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Binding input for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::bind_int (OCIStmt *s, const char *name, int *buf)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, mErrorHandle,
                      (OraText*) name, strlen(name),
                      buf, sizeof(int), SQLT_INT,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Binding input for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::bind_uint (OCIStmt *s, const char *name, unsigned int *buf)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, mErrorHandle,
                      (OraText*) name, strlen(name),
                      buf, sizeof(unsigned int), SQLT_UIN,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Binding input for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::bind_uint16 (OCIStmt *s, const char *name, uint16_t *buf)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, mErrorHandle,
                      (OraText*) name, strlen(name),
                      buf, sizeof(uint16_t), SQLT_UIN,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Binding input for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::bind_uint16_ind (OCIStmt *s, const char *name, uint16_t *buf,
                                sb2 *ind)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, mErrorHandle,
                      (OraText*) name, strlen(name),
                      buf, sizeof(uint16_t), SQLT_UIN,
                      ind, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Binding input for Oracle statement", mErrorHandle);
  }
}

void
OracleBackend::bind_uint32 (OCIStmt *s, const char *name, uint32_t *buf)
{
  sword err;
  OCIBind *handle = NULL;

  err = OCIBindByName(s, &handle, mErrorHandle,
                      (OraText*) name, strlen(name),
                      buf, sizeof(uint32_t), SQLT_UIN,
                      NULL, NULL, NULL, 0, NULL,
                      OCI_DEFAULT);

  if (err == OCI_ERROR) {
    throw OracleException("Binding input for Oracle statement", mErrorHandle);
  }
}


class OracleFactory : public BackendFactory
{
private:
  pthread_mutex_t factoryLock;
  OCIEnv *mEnvironmentHandle;
  OCIError *mErrorHandle;
  OCISPool *mSessionPoolHandle;
  text *mSessionPoolName;
  ub4 mSessionPoolNameLen;

  void CreateSessionPool ()
  {
    sword err;

    try {
      // Initialize and create the environment
      err = OCIEnvCreate(&mEnvironmentHandle, OCI_THREADED, NULL, NULL,
                         NULL, NULL, 0, NULL);
      if (err == OCI_ERROR) {
        throw OracleException("OCIEnvCreate");
      }
      // Allocate an error handle
      err = OCIHandleAlloc(mEnvironmentHandle, (void**) &mErrorHandle,
                           OCI_HTYPE_ERROR, 0, NULL);
      if (err == OCI_ERROR) {
        throw OracleException("OCIHandleAlloc");
      }

      const char *dbname = arg()["oracle-database"].c_str();
      const char *dbuser = arg()["oracle-username"].c_str();
      const char *dbpass = arg()["oracle-password"].c_str();

      ub4 sess_min = arg().asNum("oracle-session-min");
      ub4 sess_max = arg().asNum("oracle-session-max");
      ub4 sess_inc = arg().asNum("oracle-session-inc");

      // Create a session pool
      err = OCIHandleAlloc(mEnvironmentHandle, (void**) &mSessionPoolHandle,
                           OCI_HTYPE_SPOOL, 0, NULL);
      if (err == OCI_ERROR) {
        throw OracleException("OCIHandleAlloc");
      }
      err = OCISessionPoolCreate(mEnvironmentHandle, mErrorHandle,
                                 mSessionPoolHandle,
                                 (OraText **) &mSessionPoolName,
                                 &mSessionPoolNameLen,
                                 (OraText *) dbname, strlen(dbname),
                                 sess_min, sess_max, sess_inc,
                                 (OraText *) dbuser, strlen(dbuser),
                                 (OraText *) dbpass, strlen(dbpass),
                                 OCI_SPC_STMTCACHE | OCI_SPC_HOMOGENEOUS);
      if (err == OCI_ERROR) {
        throw OracleException("Creating Oracle session pool", mErrorHandle);
      }
    } catch (OracleException &theException) {
      L << Logger::Critical << "OracleFactory: "
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
        err = OCISessionPoolDestroy(mSessionPoolHandle, mErrorHandle,
                                    OCI_SPD_FORCE);
        OCIHandleFree(mSessionPoolHandle, OCI_HTYPE_SPOOL);
        mSessionPoolHandle = NULL;
        if (err == OCI_ERROR) {
          throw OracleException("OCISessionPoolDestroy", mErrorHandle);
        }
      } catch (OracleException &theException) {
        L << Logger::Error << "Failed to destroy Oracle session pool: "
          << theException.reason << endl;
      }
    }

    if (mErrorHandle != NULL) {
      OCIHandleFree(mErrorHandle, OCI_HTYPE_ERROR);
      mErrorHandle = NULL;
    }

    if (mEnvironmentHandle != NULL) {
      OCIHandleFree(mEnvironmentHandle, OCI_HTYPE_ENV);
      mEnvironmentHandle = NULL;
    }
  }

public:

OracleFactory () : BackendFactory("oracle") {
    pthread_mutex_init(&factoryLock, NULL);
    mEnvironmentHandle = NULL;
    mErrorHandle = NULL;
    mSessionPoolHandle = NULL;
    mSessionPoolName = NULL;
    mSessionPoolNameLen = 0;
  }

  ~OracleFactory () {
    Cleanup();
    pthread_mutex_destroy(&factoryLock);
  }

  void declareArguments (const string & suffix = "") {
    declare(suffix, "database", "Database to connect to", "powerdns");
    declare(suffix, "username", "Username to connect as", "powerdns");
    declare(suffix, "password", "Password to connect with", "");
    declare(suffix,
            "session-min", "Number of sessions to open at startup", "4");
    declare(suffix,
            "session-inc", "Number of sessions to open when growing", "2");
    declare(suffix,
            "session-max", "Max number of sessions to have open", "20");

    declare(suffix, "nameserver-name", "", "");

    declare(suffix, "basic-query", "", basicQueryDefaultSQL);
    declare(suffix, "basic-id-query", "", basicIdQueryDefaultSQL);
    declare(suffix, "any-query", "", anyQueryDefaultSQL);
    declare(suffix, "any-id-query", "", anyIdQueryDefaultSQL);
    declare(suffix, "list-query", "", listQueryDefaultSQL);
    declare(suffix, "zone-info-query", "", zoneInfoQueryDefaultSQL);
    declare(suffix, "also-notify-query", "", alsoNotifyQueryDefaultSQL);
    declare(suffix, "check-acl-query", "", checkACLQueryDefaultSQL);
    declare(suffix, "zone-masters-query", "", zoneMastersQueryDefaultSQL);
    declare(suffix, "is-zone-master-query", "", isZoneMasterQueryDefaultSQL);
    declare(suffix, "delete-zone-query", "", deleteZoneQueryDefaultSQL);
    declare(suffix, "zone-set-last-check-query", "", zoneSetLastCheckQueryDefaultSQL);
    declare(suffix, "zone-set-notified-serial-query", "", zoneSetNotifiedSerialQueryDefaultSQL);
    declare(suffix, "insert-record-query", "", insertRecordQueryDefaultSQL);
    declare(suffix, "unfresh-zones-query", "", unfreshZonesQueryDefaultSQL);
    declare(suffix, "updated-masters-query", "", updatedMastersQueryDefaultSQL);
    declare(suffix, "accept-supernotification-query", "", acceptSupernotificationQueryDefaultSQL);
    declare(suffix, "insert-slave-query", "", insertSlaveQueryDefaultSQL);
    declare(suffix, "insert-master-query", "", insertMasterQueryDefaultSQL);
    declare(suffix, "prev-next-name-query", "", prevNextNameQueryDefaultSQL);
    declare(suffix, "prev-next-hash-query", "", prevNextHashQueryDefaultSQL);

    declare(suffix, "get-zone-metadata-query", "", getZoneMetadataQueryDefaultSQL);
    declare(suffix, "del-zone-metadata-query", "", delZoneMetadataQueryDefaultSQL);
    declare(suffix, "set-zone-metadata-query", "", setZoneMetadataQueryDefaultSQL);

    declare(suffix, "get-zone-keys-query", "", getZoneKeysQueryDefaultSQL);
    declare(suffix, "del-zone-key-query", "", delZoneKeyQueryDefaultSQL);
    declare(suffix, "add-zone-key-query", "", addZoneKeyQueryDefaultSQL);
    declare(suffix, "set-zone-key-state-query", "", setZoneKeyStateQueryDefaultSQL);
  }

  DNSBackend *make (const string & suffix = "") {
    {
      Lock l(&factoryLock);
      if (mEnvironmentHandle == NULL) {
        CreateSessionPool();
      }
    }
    return new OracleBackend(suffix, mEnvironmentHandle,
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
  }

};

static OracleLoader loader;

/* vi: set sw=2 et : */
