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
    if(d_db)
      delete d_db;    
  }
  
  void setDB(SSql *db)
  {
    freeStatements();
    delete d_db;
    d_db=db;
    if (d_db) {
      d_db->setLog(::arg().mustDo("query-logging"));
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
      d_ZoneLastChangeQuery_stmt = d_db->prepare(d_ZoneLastChangeQuery, 1);
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

  void release(SSqlStatement **stmt) {
    delete *stmt;
    *stmt = NULL;
  }
  
  void freeStatements() {
    release(&d_NoIdQuery_stmt);
    release(&d_IdQuery_stmt);
    release(&d_ANYNoIdQuery_stmt);
    release(&d_ANYIdQuery_stmt);
    release(&d_listQuery_stmt);
    release(&d_listSubZoneQuery_stmt);
    release(&d_MasterOfDomainsZoneQuery_stmt);
    release(&d_InfoOfDomainsZoneQuery_stmt);
    release(&d_InfoOfAllSlaveDomainsQuery_stmt);
    release(&d_SuperMasterInfoQuery_stmt);
    release(&d_GetSuperMasterIPs_stmt);
    release(&d_InsertZoneQuery_stmt);
    release(&d_InsertRecordQuery_stmt);
    release(&d_InsertEmptyNonTerminalOrderQuery_stmt);
    release(&d_UpdateMasterOfZoneQuery_stmt);
    release(&d_UpdateKindOfZoneQuery_stmt);
    release(&d_UpdateAccountOfZoneQuery_stmt);
    release(&d_UpdateSerialOfZoneQuery_stmt);
    release(&d_UpdateLastCheckofZoneQuery_stmt);
    release(&d_InfoOfAllMasterDomainsQuery_stmt);
    release(&d_DeleteDomainQuery_stmt);
    release(&d_DeleteZoneQuery_stmt);
    release(&d_DeleteRRSetQuery_stmt);
    release(&d_DeleteNamesQuery_stmt);
    release(&d_ZoneLastChangeQuery_stmt);
    release(&d_firstOrderQuery_stmt);
    release(&d_beforeOrderQuery_stmt);
    release(&d_afterOrderQuery_stmt);
    release(&d_lastOrderQuery_stmt);
    release(&d_updateOrderNameAndAuthQuery_stmt);
    release(&d_updateOrderNameAndAuthTypeQuery_stmt);
    release(&d_nullifyOrderNameAndUpdateAuthQuery_stmt);
    release(&d_nullifyOrderNameAndUpdateAuthTypeQuery_stmt);
    release(&d_RemoveEmptyNonTerminalsFromZoneQuery_stmt);
    release(&d_DeleteEmptyNonTerminalQuery_stmt);
    release(&d_AddDomainKeyQuery_stmt);
    release(&d_GetLastInsertedKeyIdQuery_stmt);
    release(&d_ListDomainKeysQuery_stmt);
    release(&d_GetAllDomainMetadataQuery_stmt);
    release(&d_GetDomainMetadataQuery_stmt);
    release(&d_ClearDomainMetadataQuery_stmt);
    release(&d_ClearDomainAllMetadataQuery_stmt);
    release(&d_SetDomainMetadataQuery_stmt);
    release(&d_RemoveDomainKeyQuery_stmt);
    release(&d_ActivateDomainKeyQuery_stmt);
    release(&d_DeactivateDomainKeyQuery_stmt);
    release(&d_ClearDomainAllKeysQuery_stmt);
    release(&d_getTSIGKeyQuery_stmt);
    release(&d_setTSIGKeyQuery_stmt);
    release(&d_deleteTSIGKeyQuery_stmt);
    release(&d_getTSIGKeysQuery_stmt);
    release(&d_getAllDomainsQuery_stmt);
    release(&d_ListCommentsQuery_stmt);
    release(&d_InsertCommentQuery_stmt);
    release(&d_DeleteCommentRRsetQuery_stmt);
    release(&d_DeleteCommentsQuery_stmt);
    release(&d_SearchRecordsQuery_stmt);
    release(&d_SearchCommentsQuery_stmt);
  }

  void lookup(const QType &, const DNSName &qdomain, DNSPacket *p=0, int zoneId=-1) override;
  bool list(const DNSName &target, int domain_id, bool include_disabled=false) override;
  bool get(DNSResourceRecord &r) override;
  void getAllDomains(vector<DomainInfo> *domains, bool include_disabled=false) override;
  bool isMaster(const DNSName &domain, const string &ip) override;
  void alsoNotifies(const DNSName &domain, set<string> *ips) override;
  bool startTransaction(const DNSName &domain, int domain_id=-1) override;
  bool commitTransaction() override;
  bool abortTransaction() override;
  bool feedRecord(const DNSResourceRecord &r, const DNSName &ordername) override;
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
  bool getDomainInfo(const DNSName &domain, DomainInfo &di) override;
  void setNotified(uint32_t domain_id, uint32_t serial) override;
  bool setMaster(const DNSName &domain, const string &ip) override;
  bool setKind(const DNSName &domain, const DomainInfo::DomainKind kind) override;
  bool setAccount(const DNSName &domain, const string &account) override;

  bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;
  bool updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t=QType::ANY) override;

  bool updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert ,set<DNSName>& erase, bool remove) override;
  bool doesDNSSEC() override;

  bool calculateSOASerial(const DNSName& domain, const SOAData& sd, time_t& serial) override;

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
  string d_ZoneLastChangeQuery;

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

  SSqlStatement* d_query_stmt;

  SSqlStatement* d_NoIdQuery_stmt;
  SSqlStatement* d_IdQuery_stmt;
  SSqlStatement* d_ANYNoIdQuery_stmt;
  SSqlStatement* d_ANYIdQuery_stmt;
  SSqlStatement* d_listQuery_stmt;
  SSqlStatement* d_listSubZoneQuery_stmt;
  SSqlStatement* d_MasterOfDomainsZoneQuery_stmt;
  SSqlStatement* d_InfoOfDomainsZoneQuery_stmt;
  SSqlStatement* d_InfoOfAllSlaveDomainsQuery_stmt;
  SSqlStatement* d_SuperMasterInfoQuery_stmt;
  SSqlStatement* d_GetSuperMasterIPs_stmt;
  SSqlStatement* d_InsertZoneQuery_stmt;
  SSqlStatement* d_InsertRecordQuery_stmt;
  SSqlStatement* d_InsertEmptyNonTerminalOrderQuery_stmt;
  SSqlStatement* d_UpdateMasterOfZoneQuery_stmt;
  SSqlStatement* d_UpdateKindOfZoneQuery_stmt;
  SSqlStatement* d_UpdateAccountOfZoneQuery_stmt;
  SSqlStatement* d_UpdateSerialOfZoneQuery_stmt;
  SSqlStatement* d_UpdateLastCheckofZoneQuery_stmt;
  SSqlStatement* d_InfoOfAllMasterDomainsQuery_stmt;
  SSqlStatement* d_DeleteDomainQuery_stmt;
  SSqlStatement* d_DeleteZoneQuery_stmt;
  SSqlStatement* d_DeleteRRSetQuery_stmt;
  SSqlStatement* d_DeleteNamesQuery_stmt;
  SSqlStatement* d_ZoneLastChangeQuery_stmt;
  SSqlStatement* d_firstOrderQuery_stmt;
  SSqlStatement* d_beforeOrderQuery_stmt;
  SSqlStatement* d_afterOrderQuery_stmt;
  SSqlStatement* d_lastOrderQuery_stmt;
  SSqlStatement* d_updateOrderNameAndAuthQuery_stmt;
  SSqlStatement* d_updateOrderNameAndAuthTypeQuery_stmt;
  SSqlStatement* d_nullifyOrderNameAndUpdateAuthQuery_stmt;
  SSqlStatement* d_nullifyOrderNameAndUpdateAuthTypeQuery_stmt;
  SSqlStatement* d_RemoveEmptyNonTerminalsFromZoneQuery_stmt;
  SSqlStatement* d_DeleteEmptyNonTerminalQuery_stmt;
  SSqlStatement* d_AddDomainKeyQuery_stmt;
  SSqlStatement* d_GetLastInsertedKeyIdQuery_stmt;
  SSqlStatement* d_ListDomainKeysQuery_stmt;
  SSqlStatement* d_GetAllDomainMetadataQuery_stmt;
  SSqlStatement* d_GetDomainMetadataQuery_stmt;
  SSqlStatement* d_ClearDomainMetadataQuery_stmt;
  SSqlStatement* d_ClearDomainAllMetadataQuery_stmt;
  SSqlStatement* d_SetDomainMetadataQuery_stmt;
  SSqlStatement* d_RemoveDomainKeyQuery_stmt;
  SSqlStatement* d_ActivateDomainKeyQuery_stmt;
  SSqlStatement* d_DeactivateDomainKeyQuery_stmt;
  SSqlStatement* d_ClearDomainAllKeysQuery_stmt;
  SSqlStatement* d_getTSIGKeyQuery_stmt;
  SSqlStatement* d_setTSIGKeyQuery_stmt;
  SSqlStatement* d_deleteTSIGKeyQuery_stmt;
  SSqlStatement* d_getTSIGKeysQuery_stmt;
  SSqlStatement* d_getAllDomainsQuery_stmt;
  SSqlStatement* d_ListCommentsQuery_stmt;
  SSqlStatement* d_InsertCommentQuery_stmt;
  SSqlStatement* d_DeleteCommentRRsetQuery_stmt;
  SSqlStatement* d_DeleteCommentsQuery_stmt;
  SSqlStatement* d_SearchRecordsQuery_stmt;
  SSqlStatement* d_SearchCommentsQuery_stmt;

protected:
  SSql *d_db{nullptr};
  bool d_dnssecQueries;
  bool d_inTransaction{false};
};

#endif /* PDNS_GSQLBACKEND_HH */
