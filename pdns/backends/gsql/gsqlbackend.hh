/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
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
#ifndef PDNS_GSQLBACKEND_HH
#define PDNS_GSQLBACKEND_HH

#include <string>
#include <map>
#include "ssql.hh"
#include "pdns/arguments.hh"

#include "pdns/namespaces.hh"

bool isDnssecDomainMetadata (const string& name);

/* 
GSQLBackend is a generic backend used by other sql backends
*/
class GSQLBackend : public DNSBackend
{
public:
  GSQLBackend(const string &mode, const string &suffix); //!< Makes our connection to the database. Throws an exception if it fails.
  virtual ~GSQLBackend()
  {
    freeStatements();
    d_db.reset();
  }
  
  void setDB(SSql *db)
  {
    freeStatements();
    d_db=std::unique_ptr<SSql>(db);
    if (d_db) {
      d_db->setLog(::arg().mustDo("query-logging"));
      allocateStatements();
    }
  }

  void allocateStatements()
  {
    if (d_db) {
      d_NoIdQuery_stmt = d_db->prepare(d_NoIdQuery, 2);
      d_IdQuery_stmt = d_db->prepare(d_IdQuery, 3);
      d_ANYNoIdQuery_stmt = d_db->prepare(d_ANYNoIdQuery, 1);
      d_ANYIdQuery_stmt = d_db->prepare(d_ANYIdQuery, 2);
      d_listQuery_stmt = d_db->prepare(d_listQuery, 2);
      d_listSubZoneQuery_stmt = d_db->prepare(d_listSubZoneQuery, 3);
      d_MasterOfDomainsZoneQuery_stmt = d_db->prepare(d_MasterOfDomainsZoneQuery, 1);
      d_InfoOfDomainsZoneQuery_stmt = d_db->prepare(d_InfoOfDomainsZoneQuery, 1);
      d_InfoOfAllSlaveDomainsQuery_stmt = d_db->prepare(d_InfoOfAllSlaveDomainsQuery, 0);
      d_SuperMasterInfoQuery_stmt = d_db->prepare(d_SuperMasterInfoQuery, 2);
      d_GetSuperMasterIPs_stmt = d_db->prepare(d_GetSuperMasterIPs, 2);
      d_InsertZoneQuery_stmt = d_db->prepare(d_InsertZoneQuery, 4);
      d_InsertRecordQuery_stmt = d_db->prepare(d_InsertRecordQuery, 9);
      d_InsertEmptyNonTerminalOrderQuery_stmt = d_db->prepare(d_InsertEmptyNonTerminalOrderQuery, 4);
      d_UpdateMasterOfZoneQuery_stmt = d_db->prepare(d_UpdateMasterOfZoneQuery, 2);
      d_UpdateKindOfZoneQuery_stmt = d_db->prepare(d_UpdateKindOfZoneQuery, 2);
      d_UpdateAccountOfZoneQuery_stmt = d_db->prepare(d_UpdateAccountOfZoneQuery, 2);
      d_UpdateSerialOfZoneQuery_stmt = d_db->prepare(d_UpdateSerialOfZoneQuery, 2);
      d_UpdateLastCheckofZoneQuery_stmt = d_db->prepare(d_UpdateLastCheckofZoneQuery, 2);
      d_InfoOfAllMasterDomainsQuery_stmt = d_db->prepare(d_InfoOfAllMasterDomainsQuery, 0);
      d_DeleteDomainQuery_stmt = d_db->prepare(d_DeleteDomainQuery, 1);
      d_DeleteZoneQuery_stmt = d_db->prepare(d_DeleteZoneQuery, 1);
      d_DeleteRRSetQuery_stmt = d_db->prepare(d_DeleteRRSetQuery, 3);
      d_DeleteNamesQuery_stmt = d_db->prepare(d_DeleteNamesQuery, 2);
      d_firstOrderQuery_stmt = d_db->prepare(d_firstOrderQuery, 1);
      d_beforeOrderQuery_stmt = d_db->prepare(d_beforeOrderQuery, 2);
      d_afterOrderQuery_stmt = d_db->prepare(d_afterOrderQuery, 2);
      d_lastOrderQuery_stmt = d_db->prepare(d_lastOrderQuery, 1);
      d_updateOrderNameAndAuthQuery_stmt = d_db->prepare(d_updateOrderNameAndAuthQuery, 4);
      d_updateOrderNameAndAuthTypeQuery_stmt = d_db->prepare(d_updateOrderNameAndAuthTypeQuery, 5);
      d_nullifyOrderNameAndUpdateAuthQuery_stmt = d_db->prepare(d_nullifyOrderNameAndUpdateAuthQuery, 3);
      d_nullifyOrderNameAndUpdateAuthTypeQuery_stmt = d_db->prepare(d_nullifyOrderNameAndUpdateAuthTypeQuery, 4);
      d_RemoveEmptyNonTerminalsFromZoneQuery_stmt = d_db->prepare(d_RemoveEmptyNonTerminalsFromZoneQuery, 1);
      d_DeleteEmptyNonTerminalQuery_stmt = d_db->prepare(d_DeleteEmptyNonTerminalQuery, 2);
      d_AddDomainKeyQuery_stmt = d_db->prepare(d_AddDomainKeyQuery, 4);
      d_GetLastInsertedKeyIdQuery_stmt = d_db->prepare(d_GetLastInsertedKeyIdQuery, 0);
      d_ListDomainKeysQuery_stmt = d_db->prepare(d_ListDomainKeysQuery, 1);
      d_GetAllDomainMetadataQuery_stmt = d_db->prepare(d_GetAllDomainMetadataQuery, 1);
      d_GetDomainMetadataQuery_stmt = d_db->prepare(d_GetDomainMetadataQuery, 2);
      d_ClearDomainMetadataQuery_stmt = d_db->prepare(d_ClearDomainMetadataQuery, 2);
      d_ClearDomainAllMetadataQuery_stmt = d_db->prepare(d_ClearDomainAllMetadataQuery, 1);
      d_SetDomainMetadataQuery_stmt = d_db->prepare(d_SetDomainMetadataQuery, 3);
      d_RemoveDomainKeyQuery_stmt = d_db->prepare(d_RemoveDomainKeyQuery, 2);
      d_ActivateDomainKeyQuery_stmt = d_db->prepare(d_ActivateDomainKeyQuery, 2);
      d_DeactivateDomainKeyQuery_stmt = d_db->prepare(d_DeactivateDomainKeyQuery, 2);
      d_ClearDomainAllKeysQuery_stmt = d_db->prepare(d_ClearDomainAllKeysQuery, 1);
      d_getTSIGKeyQuery_stmt = d_db->prepare(d_getTSIGKeyQuery, 1);
      d_setTSIGKeyQuery_stmt = d_db->prepare(d_setTSIGKeyQuery, 3);
      d_deleteTSIGKeyQuery_stmt = d_db->prepare(d_deleteTSIGKeyQuery, 1);
      d_getTSIGKeysQuery_stmt = d_db->prepare(d_getTSIGKeysQuery, 0);
      d_getAllDomainsQuery_stmt = d_db->prepare(d_getAllDomainsQuery, 1);
      d_ListCommentsQuery_stmt = d_db->prepare(d_ListCommentsQuery, 1);
      d_InsertCommentQuery_stmt = d_db->prepare(d_InsertCommentQuery, 6);
      d_DeleteCommentRRsetQuery_stmt = d_db->prepare(d_DeleteCommentRRsetQuery, 3);
      d_DeleteCommentsQuery_stmt = d_db->prepare(d_DeleteCommentsQuery, 1);
      d_SearchRecordsQuery_stmt = d_db->prepare(d_SearchRecordsQuery, 3);
      d_SearchCommentsQuery_stmt = d_db->prepare(d_SearchCommentsQuery, 3);
    }
  }

  void freeStatements() {
    d_NoIdQuery_stmt.reset();
    d_IdQuery_stmt.reset();
    d_ANYNoIdQuery_stmt.reset();
    d_ANYIdQuery_stmt.reset();
    d_listQuery_stmt.reset();
    d_listSubZoneQuery_stmt.reset();
    d_MasterOfDomainsZoneQuery_stmt.reset();
    d_InfoOfDomainsZoneQuery_stmt.reset();
    d_InfoOfAllSlaveDomainsQuery_stmt.reset();
    d_SuperMasterInfoQuery_stmt.reset();
    d_GetSuperMasterIPs_stmt.reset();
    d_InsertZoneQuery_stmt.reset();
    d_InsertRecordQuery_stmt.reset();
    d_InsertEmptyNonTerminalOrderQuery_stmt.reset();
    d_UpdateMasterOfZoneQuery_stmt.reset();
    d_UpdateKindOfZoneQuery_stmt.reset();
    d_UpdateAccountOfZoneQuery_stmt.reset();
    d_UpdateSerialOfZoneQuery_stmt.reset();
    d_UpdateLastCheckofZoneQuery_stmt.reset();
    d_InfoOfAllMasterDomainsQuery_stmt.reset();
    d_DeleteDomainQuery_stmt.reset();
    d_DeleteZoneQuery_stmt.reset();
    d_DeleteRRSetQuery_stmt.reset();
    d_DeleteNamesQuery_stmt.reset();
    d_firstOrderQuery_stmt.reset();
    d_beforeOrderQuery_stmt.reset();
    d_afterOrderQuery_stmt.reset();
    d_lastOrderQuery_stmt.reset();
    d_updateOrderNameAndAuthQuery_stmt.reset();
    d_updateOrderNameAndAuthTypeQuery_stmt.reset();
    d_nullifyOrderNameAndUpdateAuthQuery_stmt.reset();
    d_nullifyOrderNameAndUpdateAuthTypeQuery_stmt.reset();
    d_RemoveEmptyNonTerminalsFromZoneQuery_stmt.reset();
    d_DeleteEmptyNonTerminalQuery_stmt.reset();
    d_AddDomainKeyQuery_stmt.reset();
    d_GetLastInsertedKeyIdQuery_stmt.reset();
    d_ListDomainKeysQuery_stmt.reset();
    d_GetAllDomainMetadataQuery_stmt.reset();
    d_GetDomainMetadataQuery_stmt.reset();
    d_ClearDomainMetadataQuery_stmt.reset();
    d_ClearDomainAllMetadataQuery_stmt.reset();
    d_SetDomainMetadataQuery_stmt.reset();
    d_RemoveDomainKeyQuery_stmt.reset();
    d_ActivateDomainKeyQuery_stmt.reset();
    d_DeactivateDomainKeyQuery_stmt.reset();
    d_ClearDomainAllKeysQuery_stmt.reset();
    d_getTSIGKeyQuery_stmt.reset();
    d_setTSIGKeyQuery_stmt.reset();
    d_deleteTSIGKeyQuery_stmt.reset();
    d_getTSIGKeysQuery_stmt.reset();
    d_getAllDomainsQuery_stmt.reset();
    d_ListCommentsQuery_stmt.reset();
    d_InsertCommentQuery_stmt.reset();
    d_DeleteCommentRRsetQuery_stmt.reset();
    d_DeleteCommentsQuery_stmt.reset();
    d_SearchRecordsQuery_stmt.reset();
    d_SearchCommentsQuery_stmt.reset();
  }

  void lookup(const QType &, const DNSName &qdomain, int zoneId, DNSPacket *p=nullptr) override;
  bool list(const DNSName &target, int domain_id, bool include_disabled=false) override;
  bool get(DNSResourceRecord &r) override;
  void getAllDomains(vector<DomainInfo> *domains, bool include_disabled=false) override;
  void alsoNotifies(const DNSName &domain, set<string> *ips) override;
  bool startTransaction(const DNSName &domain, int domain_id=-1) override;
  bool commitTransaction() override;
  bool abortTransaction() override;
  bool feedRecord(const DNSResourceRecord &r, const DNSName &ordername, bool ordernameIsNSEC3=false) override;
  bool feedEnts(int domain_id, map<DNSName,bool>& nonterm) override;
  bool feedEnts3(int domain_id, const DNSName &domain, map<DNSName,bool> &nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow) override;
  bool createDomain(const DNSName &domain) override {
    return createDomain(domain, "NATIVE", "", "");
  };
  bool createSlaveDomain(const string &ip, const DNSName &domain, const string &nameserver, const string &account) override;
  bool deleteDomain(const DNSName &domain) override;
  bool superMasterBackend(const string &ip, const DNSName &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db) override;
  void setFresh(uint32_t domain_id) override;
  void getUnfreshSlaveInfos(vector<DomainInfo> *domains) override;
  void getUpdatedMasters(vector<DomainInfo> *updatedDomains) override;
  bool getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial=true) override;
  void setNotified(uint32_t domain_id, uint32_t serial) override;
  bool setMaster(const DNSName &domain, const string &ip) override;
  bool setKind(const DNSName &domain, const DomainInfo::DomainKind kind) override;
  bool setAccount(const DNSName &domain, const string &account) override;

  bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;
  bool updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t=QType::ANY) override;

  bool updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert ,set<DNSName>& erase, bool remove) override;
  bool doesDNSSEC() override;

  bool replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset) override;
  bool listSubZone(const DNSName &zone, int domain_id) override;
  bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) override;
  bool getDomainKeys(const DNSName& name, std::vector<KeyData>& keys) override;
  bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta) override;
  bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) override;
  bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta) override;
  
  bool removeDomainKey(const DNSName& name, unsigned int id) override;
  bool activateDomainKey(const DNSName& name, unsigned int id) override;
  bool deactivateDomainKey(const DNSName& name, unsigned int id) override;
  
  bool getTSIGKey(const DNSName& name, DNSName* algorithm, string* content) override;
  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content) override;
  bool deleteTSIGKey(const DNSName& name) override;
  bool getTSIGKeys(std::vector< struct TSIGKey > &keys) override;

  bool listComments(const uint32_t domain_id) override;
  bool getComment(Comment& comment) override;
  void feedComment(const Comment& comment) override;
  bool replaceComments(const uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<Comment>& comments) override;
  string directBackendCmd(const string &query) override;
  bool searchRecords(const string &pattern, int maxResults, vector<DNSResourceRecord>& result) override;
  bool searchComments(const string &pattern, int maxResults, vector<Comment>& result) override;

protected:
  bool createDomain(const DNSName &domain, const string &type, const string &masters, const string &account);
  string pattern2SQLPattern(const string& pattern);
  void extractRecord(const SSqlStatement::row_t& row, DNSResourceRecord& rr);
  void extractComment(const SSqlStatement::row_t& row, Comment& c);
  bool isConnectionUsable() {
    if (d_db) {
      return d_db->isConnectionUsable();
    }
    return false;
  }
  void reconnectIfNeeded()
  {
    if (inTransaction() || isConnectionUsable()) {
      return;
    }

    reconnect();
  }
  virtual void reconnect() { }
  virtual bool inTransaction()
  {
    return d_inTransaction;
  }

private:
  string d_query_name;
  DNSName d_qname;
  SSqlStatement::result_t d_result;

  string d_NoIdQuery;
  string d_IdQuery;
  string d_ANYNoIdQuery;
  string d_ANYIdQuery;

  string d_listQuery;
  string d_listSubZoneQuery;
  string d_logprefix;

  string d_MasterOfDomainsZoneQuery;
  string d_InfoOfDomainsZoneQuery;
  string d_InfoOfAllSlaveDomainsQuery;
  string d_SuperMasterInfoQuery;
  string d_GetSuperMasterName;
  string d_GetSuperMasterIPs;

  string d_InsertZoneQuery;
  string d_InsertRecordQuery;
  string d_InsertEmptyNonTerminalOrderQuery;
  string d_UpdateMasterOfZoneQuery;
  string d_UpdateKindOfZoneQuery;
  string d_UpdateAccountOfZoneQuery;
  string d_UpdateSerialOfZoneQuery;
  string d_UpdateLastCheckofZoneQuery;
  string d_InfoOfAllMasterDomainsQuery;
  string d_DeleteDomainQuery;
  string d_DeleteZoneQuery;
  string d_DeleteRRSetQuery;
  string d_DeleteNamesQuery;

  string d_firstOrderQuery;
  string d_beforeOrderQuery;
  string d_afterOrderQuery;
  string d_lastOrderQuery;

  string d_updateOrderNameAndAuthQuery;
  string d_updateOrderNameAndAuthTypeQuery;
  string d_nullifyOrderNameAndUpdateAuthQuery;
  string d_nullifyOrderNameAndUpdateAuthTypeQuery;

  string d_RemoveEmptyNonTerminalsFromZoneQuery;
  string d_DeleteEmptyNonTerminalQuery;

  string d_AddDomainKeyQuery;
  string d_GetLastInsertedKeyIdQuery;
  string d_ListDomainKeysQuery;
  string d_GetAllDomainMetadataQuery;
  string d_GetDomainMetadataQuery;
  string d_ClearDomainMetadataQuery;
  string d_ClearDomainAllMetadataQuery;
  string d_SetDomainMetadataQuery;

  string d_RemoveDomainKeyQuery;
  string d_ActivateDomainKeyQuery;
  string d_DeactivateDomainKeyQuery;
  string d_ClearDomainAllKeysQuery;

  string d_getTSIGKeyQuery;
  string d_setTSIGKeyQuery;
  string d_deleteTSIGKeyQuery;
  string d_getTSIGKeysQuery;

  string d_getAllDomainsQuery;

  string d_ListCommentsQuery;
  string d_InsertCommentQuery;
  string d_DeleteCommentRRsetQuery;
  string d_DeleteCommentsQuery;

  string d_SearchRecordsQuery;
  string d_SearchCommentsQuery;

  unique_ptr<SSqlStatement>* d_query_stmt;

  unique_ptr<SSqlStatement> d_NoIdQuery_stmt;
  unique_ptr<SSqlStatement> d_IdQuery_stmt;
  unique_ptr<SSqlStatement> d_ANYNoIdQuery_stmt;
  unique_ptr<SSqlStatement> d_ANYIdQuery_stmt;
  unique_ptr<SSqlStatement> d_listQuery_stmt;
  unique_ptr<SSqlStatement> d_listSubZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_MasterOfDomainsZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_InfoOfDomainsZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_InfoOfAllSlaveDomainsQuery_stmt;
  unique_ptr<SSqlStatement> d_SuperMasterInfoQuery_stmt;
  unique_ptr<SSqlStatement> d_GetSuperMasterIPs_stmt;
  unique_ptr<SSqlStatement> d_InsertZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_InsertRecordQuery_stmt;
  unique_ptr<SSqlStatement> d_InsertEmptyNonTerminalOrderQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateMasterOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateKindOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateAccountOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateSerialOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateLastCheckofZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_InfoOfAllMasterDomainsQuery_stmt;
  unique_ptr<SSqlStatement> d_DeleteDomainQuery_stmt;
  unique_ptr<SSqlStatement> d_DeleteZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_DeleteRRSetQuery_stmt;
  unique_ptr<SSqlStatement> d_DeleteNamesQuery_stmt;
  unique_ptr<SSqlStatement> d_firstOrderQuery_stmt;
  unique_ptr<SSqlStatement> d_beforeOrderQuery_stmt;
  unique_ptr<SSqlStatement> d_afterOrderQuery_stmt;
  unique_ptr<SSqlStatement> d_lastOrderQuery_stmt;
  unique_ptr<SSqlStatement> d_updateOrderNameAndAuthQuery_stmt;
  unique_ptr<SSqlStatement> d_updateOrderNameAndAuthTypeQuery_stmt;
  unique_ptr<SSqlStatement> d_nullifyOrderNameAndUpdateAuthQuery_stmt;
  unique_ptr<SSqlStatement> d_nullifyOrderNameAndUpdateAuthTypeQuery_stmt;
  unique_ptr<SSqlStatement> d_RemoveEmptyNonTerminalsFromZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_DeleteEmptyNonTerminalQuery_stmt;
  unique_ptr<SSqlStatement> d_AddDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_GetLastInsertedKeyIdQuery_stmt;
  unique_ptr<SSqlStatement> d_ListDomainKeysQuery_stmt;
  unique_ptr<SSqlStatement> d_GetAllDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_GetDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_ClearDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_ClearDomainAllMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_SetDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_RemoveDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_ActivateDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_DeactivateDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_ClearDomainAllKeysQuery_stmt;
  unique_ptr<SSqlStatement> d_getTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_setTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_deleteTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_getTSIGKeysQuery_stmt;
  unique_ptr<SSqlStatement> d_getAllDomainsQuery_stmt;
  unique_ptr<SSqlStatement> d_ListCommentsQuery_stmt;
  unique_ptr<SSqlStatement> d_InsertCommentQuery_stmt;
  unique_ptr<SSqlStatement> d_DeleteCommentRRsetQuery_stmt;
  unique_ptr<SSqlStatement> d_DeleteCommentsQuery_stmt;
  unique_ptr<SSqlStatement> d_SearchRecordsQuery_stmt;
  unique_ptr<SSqlStatement> d_SearchCommentsQuery_stmt;

protected:
  std::unique_ptr<SSql> d_db{nullptr};
  bool d_dnssecQueries;
  bool d_inTransaction{false};
};

#endif /* PDNS_GSQLBACKEND_HH */
