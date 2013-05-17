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
#include <map>
#include <fstream>

#include <oci.h>

#include "pdns/namespaces.hh"

class OracleException : public DBException
{
public:

  OracleException (string r) : DBException(r) {}

  OracleException (string context, OCIError *theErrorHandle)
    : DBException(context + ": ORA-UNKNOWN")
  {
    if (theErrorHandle != NULL) {
      char msg[2048];
      sb4 errcode = 0;

      msg[0] = '\0';

      OCIErrorGet((void *) theErrorHandle, 1, NULL, &errcode, (OraText*) msg,
                  sizeof(msg), OCI_HTYPE_ERROR);

      reason = context + ": " + msg;
    }
  }

};

class OracleBackend : public DNSBackend
{
public:

  OracleBackend(const string &suffix = "", OCIEnv *envh =
                NULL, char *poolname = NULL);
  virtual ~OracleBackend();

  void lookup(const QType &qtype, const string &qname, DNSPacket *p = 0,
              int zoneId = -1);
  bool getBeforeAndAfterNames(uint32_t zoneId, const string& zone,
                              const string& name,
                              string& before, string& after);
  bool getBeforeAndAfterNamesAbsolute(uint32_t zoneId,
                                      const string& name,
                                      string& unhashed,
                                      string& before,
                                      string& after);
  bool get(DNSResourceRecord &rr);
  vector<string> getDomainMasters(const string &domain, int zoneId);
  bool isMaster(const string &domain, const string &master);
  bool getDomainInfo(const string &domain, DomainInfo &di);
  void alsoNotifies(const string &domain, set<string> *addrs);
  void getUnfreshSlaveInfos(vector<DomainInfo>* domains);
  void getUpdatedMasters(vector<DomainInfo>* domains);
  void setFresh(uint32_t zoneId); // No, it's not int zoneId. Really.
  void setNotified(uint32_t zoneId, uint32_t serial); // ditto
  bool list(const string &domain, int zoneId);
  bool startTransaction(const string &domain, int zoneId);
  bool feedRecord(const DNSResourceRecord &rr);
  bool commitTransaction();
  bool abortTransaction();
  bool superMasterBackend(const string &ip, const string &domain,
                          const vector<DNSResourceRecord> &nsset,
                          string *account, DNSBackend **backend);
  bool createSlaveDomain(const string &ip, const string &domain,
                         const string &account);

  bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta);
  bool setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta);

  bool getTSIGKey(const string& name, string* algorithm, string* content);
  bool getDomainKeys(const string& name, unsigned int kind, vector<KeyData>& keys);
  bool removeDomainKey(const string& name, unsigned int id);
  int addDomainKey(const string& name, const KeyData& key);
  bool activateDomainKey(const string& name, unsigned int id);
  bool deactivateDomainKey(const string& name, unsigned int id);

private:

  OCIEnv *oraenv;
  OCIError *oraerr;
  OCISvcCtx *pooledSvcCtx;
  OCIAuthInfo *masterAuthHandle;
  OCISvcCtx *masterSvcCtx;

  string basicQuerySQL;
  string basicIdQuerySQL;
  string anyQuerySQL;
  string anyIdQuerySQL;
  string listQuerySQL;

  string zoneInfoQuerySQL;
  string alsoNotifyQuerySQL;
  string zoneMastersQuerySQL;
  string isZoneMasterQuerySQL;
  string deleteZoneQuerySQL;
  string zoneSetLastCheckQuerySQL;

  string insertRecordQuerySQL;
  string finalizeAXFRQuerySQL;

  string unfreshZonesQuerySQL;
  string updatedMastersQuerySQL;
  string acceptSupernotificationQuerySQL;
  string insertSlaveQuerySQL;
  string insertMasterQuerySQL;
  string zoneSetNotifiedSerialQuerySQL;

  string prevNextNameQuerySQL;
  string prevNextHashQuerySQL;

  string getZoneMetadataQuerySQL;
  string delZoneMetadataQuerySQL;
  string setZoneMetadataQuerySQL;

  string getTSIGKeyQuerySQL;
  string getZoneKeysQuerySQL;
  string delZoneKeyQuerySQL;
  string addZoneKeyQuerySQL;
  string setZoneKeyStateQuerySQL;

  OCIStmt *curStmtHandle;
  const char *curStmtKey;
  int openTransactionZoneID;

  char myServerName[512];

  char mQueryName[512];
  char mQueryType[64];
  char mQueryContent[4001];
  char mQueryZone[512];
  char mQueryAddr[64];
  int  mQueryZoneId;
  int  mQueryTimestamp;

  char      mResultName[512];
  sb2       mResultNameInd;
  uint32_t  mResultTTL;
  sb2       mResultTTLInd;
  char      mResultType[64];
  sb2       mResultTypeInd;
  char      mResultContent[4001];
  sb2       mResultContentInd;
  int       mResultZoneId;
  sb2       mResultZoneIdInd;
  int       mResultLastChange;
  sb2       mResultLastChangeInd;
  int       mResultIsAuth;
  sb2       mResultIsAuthInd;
  char      mResultPrevName[512];
  sb2       mResultPrevNameInd;
  char      mResultNextName[512];
  sb2       mResultNextNameInd;
  bool      d_dnssecQueries;

  void Cleanup();

  void openMasterConnection();
  bool setDomainKeyState(const string& name, unsigned int id, int active);

  OCIStmt* prepare_query (OCISvcCtx* orasvc, string& code, const char *key);
  void release_query (OCIStmt *stmt, const char *key);
  void define_output_str (OCIStmt *s, ub4 pos, sb2 *ind, char *buf, sb4 buflen);
  void define_output_int (OCIStmt *s, ub4 pos, sb2 *ind, int *buf);
  void define_output_uint (OCIStmt *s, ub4 pos, sb2 *ind, unsigned int *buf);
  void define_output_uint16 (OCIStmt *s, ub4 pos, sb2 *ind, uint16_t *buf);
  void define_output_uint32 (OCIStmt *s, ub4 pos, sb2 *ind, uint32_t *buf);
  void check_indicator (sb2 ind, bool null_okay);
  void define_fwd_query (OCIStmt *s);
  void bind_str (OCIStmt *s, const char *name, char *buf, sb4 buflen);
  void bind_str_failokay (OCIStmt *s, const char *name, char *buf, sb4 buflen);
  void bind_str_ind (OCIStmt *s, const char *name, char *buf, sb4 buflen, sb2 *ind);
  void bind_int (OCIStmt *s, const char *name, int *buf);
  void bind_uint (OCIStmt *s, const char *name, unsigned int *buf);
  void bind_uint16 (OCIStmt *s, const char *name, uint16_t *buf);
  void bind_uint16_ind (OCIStmt *s, const char *name, uint16_t *buf, sb2 *ind);
  void bind_uint32 (OCIStmt *s, const char *name, uint32_t *buf);

};

/* vi: set sw=2 et : */
