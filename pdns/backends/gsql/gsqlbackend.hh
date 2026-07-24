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
#pragma once
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
  ~GSQLBackend() override
  {
    freeStatements();
    d_db.reset();
  }

  void setDB(std::unique_ptr<SSql>&& database)
  {
    freeStatements();
    d_db = std::move(database);
    if (d_db) {
      d_db->setLog(::arg().mustDo("query-logging"));
    }
  }

protected:
  virtual void allocateStatements();
  virtual void freeStatements();

public:
  unsigned int getCapabilities() override;
  void lookup(const QType& qtype, const DNSName& qname, domainid_t domain_id, DNSPacket *p=nullptr) override;
  void APILookup(const QType &qtype, const DNSName &qname, domainid_t domain_id, bool include_disabled = false) override;
  bool list(const ZoneName &target, domainid_t domain_id, bool include_disabled=false) override;
  bool get(DNSResourceRecord &r) override;
  void getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled) override;
  bool startTransaction(const ZoneName &domain, domainid_t domain_id=UnknownDomainID) override;
  bool commitTransaction() override;
  bool abortTransaction() override;
  bool feedRecord(const DNSResourceRecord &r, const DNSName &ordername, bool ordernameIsNSEC3=false) override;
  bool feedEnts(domainid_t domain_id, map<DNSName,bool>& nonterm) override;
  bool feedEnts3(domainid_t domain_id, const DNSName &domain, map<DNSName,bool> &nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow) override;
  bool createDomain(const ZoneName& domain, const DomainInfo::DomainKind kind, const vector<ComboAddress>& primaries, const string& account, DomainInfo& info) override;
  bool createSecondaryDomain(const string& ipAddress, const ZoneName& domain, const string& nameserver, const string& account, DomainInfo& info) override;
  bool deleteDomain(const ZoneName &domain) override;
  bool autoPrimaryAdd(const AutoPrimary& primary) override;
  bool autoPrimaryRemove(const AutoPrimary& primary) override;
  bool autoPrimariesList(std::vector<AutoPrimary>& primaries) override;
  bool autoPrimaryBackend(const string& ipAddress, const ZoneName& domain, const vector<DNSResourceRecord>& nsset, string* nameserver, string* account, DNSBackend** db) override;
  void setStale(domainid_t domain_id) override;
  void setFresh(domainid_t domain_id) override;
  void getUnfreshSecondaryInfos(vector<DomainInfo>* domains) override;
  void getUpdatedPrimaries(vector<DomainInfo>& updatedDomains, std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes) override;
  bool getCatalogMembers(const ZoneName& catalog, vector<CatalogInfo>& members, CatalogInfo::CatalogType type) override;
  bool getDomainInfo(const ZoneName &domain, DomainInfo &info, bool getSerial=true) override;
  void setNotified(domainid_t domain_id, uint32_t serial) override;
  bool setPrimaries(const ZoneName& domain, const vector<ComboAddress>& primaries) override;
  bool setKind(const ZoneName &domain, const DomainInfo::DomainKind kind) override;
  bool setOptions(const ZoneName& domain, const string& options) override;
  bool setCatalog(const ZoneName& domain, const ZoneName& catalog) override;
  bool setAccount(const ZoneName &domain, const string &account) override;

  bool getBeforeAndAfterNamesAbsolute(domainid_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;
  bool updateDNSSECOrderNameAndAuth(domainid_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t, bool isNsec3) override;

  bool updateEmptyNonTerminals(domainid_t domain_id, set<DNSName>& insert ,set<DNSName>& erase, bool remove) override;

  bool replaceRRSet(domainid_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset) override;
  bool listSubZone(const ZoneName &zone, domainid_t domain_id) override;
  bool addDomainKey(const ZoneName& name, const KeyData& key, int64_t& id) override;
  bool getDomainKeys(const ZoneName& name, std::vector<KeyData>& keys) override;
  bool getAllDomainMetadata(const ZoneName& name, std::map<std::string, std::vector<std::string> >& meta) override;
  bool getDomainMetadata(const ZoneName& name, const std::string& kind, std::vector<std::string>& meta) override;
  bool setDomainMetadata(const ZoneName& name, const std::string& kind, const std::vector<std::string>& meta) override;

  bool removeDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool activateDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool deactivateDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool publishDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool unpublishDomainKey(const ZoneName& name, unsigned int keyId) override;

  bool getTSIGKey(const DNSName& name, DNSName& algorithm, string& content) override;
  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content) override;
  bool deleteTSIGKey(const DNSName& name) override;
  bool getTSIGKeys(std::vector< struct TSIGKey > &keys) override;

  bool listComments(const domainid_t domain_id) override;
  bool getComment(Comment& comment) override;
  bool feedComment(const Comment& comment) override;
  bool replaceComments(const domainid_t domain_id, const DNSName& qname, const QType& qt, const vector<Comment>& comments) override;
  string directBackendCmd(const string &query) override;
  bool searchRecords(const string &pattern, size_t maxResults, vector<DNSResourceRecord>& result) override;
  bool searchComments(const string &pattern, size_t maxResults, vector<Comment>& result) override;
  bool get_unsafe(DNSResourceRecord& rec, std::vector<std::pair<std::string, std::string>>& invalid) override;

protected:
  void extractRecord(SSqlStatement::row_t& row, DNSResourceRecord& rr);
  void extractRecord_unsafe(SSqlStatement::row_t& row, DNSResourceRecord& rec, std::vector<std::pair<std::string, std::string>>& invalid);
  void extractComment(SSqlStatement::row_t& row, Comment& c);
  void setLastCheck(domainid_t domain_id, time_t lastcheck);
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
  bool inTransaction() override
  {
    return d_inTransaction;
  }

  enum { LIST, LISTSUBZONE, OTHER } d_currentQueryType{OTHER};
  string d_query_name;
  DNSName d_qname;
  SSqlStatement::result_t d_result;
  unique_ptr<SSqlStatement>* d_query_stmt;

private:
  string d_NoIdQuery;
  string d_IdQuery;
  string d_ANYNoIdQuery;
  string d_ANYIdQuery;

  string d_APIIdQuery;
  string d_APIANYIdQuery;

  string d_listQuery;
  string d_listSubZoneQuery;
  string d_logprefix;

  string d_PrimaryOfDomainsZoneQuery;
  string d_InfoOfDomainsZoneQuery;
  string d_InfoOfAllSecondaryDomainsQuery;
  string d_AutoPrimaryInfoQuery;
  string d_GetAutoPrimaryName;
  string d_GetAutoPrimaryIPs;
  string d_AddAutoPrimary;
  string d_RemoveAutoPrimaryQuery;
  string d_ListAutoPrimariesQuery;

  string d_InsertZoneQuery;
  string d_InsertRecordQuery;
  string d_InsertEmptyNonTerminalOrderQuery;
  string d_UpdatePrimaryOfZoneQuery;
  string d_UpdateKindOfZoneQuery;
  string d_UpdateOptionsOfZoneQuery;
  string d_UpdateCatalogOfZoneQuery;
  string d_UpdateAccountOfZoneQuery;
  string d_UpdateSerialOfZoneQuery;
  string d_UpdateLastCheckOfZoneQuery;
  string d_InfoOfAllPrimaryDomainsQuery;
  string d_InfoProducerMembersQuery;
  string d_InfoConsumerMembersQuery;
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
  string d_PublishDomainKeyQuery;
  string d_UnpublishDomainKeyQuery;
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


  unique_ptr<SSqlStatement> d_NoIdQuery_stmt;
  unique_ptr<SSqlStatement> d_IdQuery_stmt;
  unique_ptr<SSqlStatement> d_ANYNoIdQuery_stmt;
  unique_ptr<SSqlStatement> d_ANYIdQuery_stmt;
  unique_ptr<SSqlStatement> d_APIIdQuery_stmt;
  unique_ptr<SSqlStatement> d_APIANYIdQuery_stmt;
  unique_ptr<SSqlStatement> d_listQuery_stmt;
  unique_ptr<SSqlStatement> d_listSubZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_PrimaryOfDomainsZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_InfoOfDomainsZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_InfoOfAllSecondaryDomainsQuery_stmt;
  unique_ptr<SSqlStatement> d_AutoPrimaryInfoQuery_stmt;
  unique_ptr<SSqlStatement> d_GetAutoPrimaryIPs_stmt;
  unique_ptr<SSqlStatement> d_AddAutoPrimary_stmt;
  unique_ptr<SSqlStatement> d_RemoveAutoPrimary_stmt;
  unique_ptr<SSqlStatement> d_ListAutoPrimaries_stmt;
  unique_ptr<SSqlStatement> d_InsertZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_InsertRecordQuery_stmt;
  unique_ptr<SSqlStatement> d_InsertEmptyNonTerminalOrderQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdatePrimaryOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateKindOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateOptionsOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateCatalogOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateAccountOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateSerialOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_UpdateLastCheckOfZoneQuery_stmt;
  unique_ptr<SSqlStatement> d_InfoOfAllPrimaryDomainsQuery_stmt;
  unique_ptr<SSqlStatement> d_InfoProducerMembersQuery_stmt;
  unique_ptr<SSqlStatement> d_InfoConsumerMembersQuery_stmt;
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
  unique_ptr<SSqlStatement> d_PublishDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_UnpublishDomainKeyQuery_stmt;
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
  bool d_upgradeContent{false};
};
