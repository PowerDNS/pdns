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
#ifndef PDNS_ORACLEBACKEND_HH
#define PDNS_ORACLEBACKEND_HH

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

  void lookup(const QType &qtype, const DNSName& qname, DNSPacket *p = 0,
              int zoneId = -1) override;

  bool getBeforeAndAfterNames(uint32_t zoneId, const DNSName& zone,
                              const DNSName& name,
                              DNSName& before, DNSName& after) override;
  bool getBeforeAndAfterNamesAbsolute(uint32_t zoneId,
                                      const DNSName& name,
                                      DNSName& unhashed,
                                      DNSName& before,
                                      DNSName& after) override;
  bool get(DNSResourceRecord &rr) override;
  vector<string> getDomainMasters(const DNSName& domain, int zoneId) override;
  bool getDomainInfo(const DNSName& domain, DomainInfo &di) override;
  void alsoNotifies(const DNSName& domain, set<string> *addrs) override;
  void getUnfreshSlaveInfos(vector<DomainInfo>* domains) override;
  void getUpdatedMasters(vector<DomainInfo>* domains) override;
  void setFresh(uint32_t zoneId) override;
  void setNotified(uint32_t zoneId, uint32_t serial) override;
  bool list(const DNSName& domain, int zoneId, bool include_disabled=false) override;
  bool startTransaction(const DNSName& domain, int zoneId) override;
  bool feedRecord(const DNSResourceRecord &rr, const DNSName ordername) override;
  bool commitTransaction() override;
  bool abortTransaction() override;
  bool superMasterBackend(const string &ip, const DNSName& domain,
                          const vector<DNSResourceRecord> &nsset,
                          string *account, string *nameserver,
                          DNSBackend **backend) override;
  bool createSlaveDomain(const string &ip, const DNSName& domain,
                         const string &nameserver, const string &account) override;

  bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta) override;
  bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) override;
  bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta) override;

  bool getTSIGKey(const DNSName& name, DNSName* algorithm, string* content) override;
  bool delTSIGKey(const DNSName& name) override;
  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content) override;
  bool getTSIGKeys(std::vector< struct TSIGKey > &keys) override;

  bool getDomainKeys(const DNSName& name, vector<KeyData>& keys) override;
  bool removeDomainKey(const DNSName& name, unsigned int id) override;
  bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) override;
  bool activateDomainKey(const DNSName& name, unsigned int id) override;
  bool deactivateDomainKey(const DNSName& name, unsigned int id) override;

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

  string getAllZoneMetadataQuerySQL;
  string getZoneMetadataQuerySQL;
  string delZoneMetadataQuerySQL;
  string setZoneMetadataQuerySQL;

  string getTSIGKeyQuerySQL;
  string delTSIGKeyQuerySQL;
  string setTSIGKeyQuerySQL;
  string getTSIGKeysQuerySQL;

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
  bool setDomainKeyState(const DNSName& name, unsigned int id, int active);

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

#endif /* PDNS_ORACLEBACKEND_HH */
