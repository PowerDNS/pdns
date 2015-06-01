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
      d_InsertZoneQuery_stmt = d_db->prepare(d_InsertZoneQuery, 1);
      d_InsertSlaveZoneQuery_stmt = d_db->prepare(d_InsertSlaveZoneQuery, 3);
      d_InsertRecordQuery_stmt = d_db->prepare(d_InsertRecordQuery, 8);
      d_InsertEntQuery_stmt = d_db->prepare(d_InsertEntQuery, 3);
      d_InsertRecordOrderQuery_stmt = d_db->prepare(d_InsertRecordOrderQuery, 9);
      d_InsertEntOrderQuery_stmt = d_db->prepare(d_InsertEntOrderQuery, 4);
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
      d_setOrderAuthQuery_stmt = d_db->prepare(d_setOrderAuthQuery, 4);
      d_nullifyOrderNameAndUpdateAuthQuery_stmt = d_db->prepare(d_nullifyOrderNameAndUpdateAuthQuery, 3);
      d_nullifyOrderNameAndAuthQuery_stmt = d_db->prepare(d_nullifyOrderNameAndAuthQuery, 3);
      d_nullifyOrderNameAndAuthENTQuery_stmt = d_db->prepare(d_nullifyOrderNameAndAuthENTQuery, 0);
      d_setAuthOnDsRecordQuery_stmt = d_db->prepare(d_setAuthOnDsRecordQuery, 2);
      d_removeEmptyNonTerminalsFromZoneQuery_stmt = d_db->prepare(d_removeEmptyNonTerminalsFromZoneQuery, 1);
      d_insertEmptyNonTerminalQuery_stmt = d_db->prepare(d_insertEmptyNonTerminalQuery, 2);
      d_deleteEmptyNonTerminalQuery_stmt = d_db->prepare(d_deleteEmptyNonTerminalQuery, 2);
      d_AddDomainKeyQuery_stmt = d_db->prepare(d_AddDomainKeyQuery, 4);
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
    release(&d_InsertSlaveZoneQuery_stmt);
    release(&d_InsertRecordQuery_stmt);
    release(&d_InsertEntQuery_stmt);
    release(&d_InsertRecordOrderQuery_stmt);
    release(&d_InsertEntOrderQuery_stmt);
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
    release(&d_setOrderAuthQuery_stmt);
    release(&d_nullifyOrderNameAndUpdateAuthQuery_stmt);
    release(&d_nullifyOrderNameAndAuthQuery_stmt);
    release(&d_nullifyOrderNameAndAuthENTQuery_stmt);
    release(&d_setAuthOnDsRecordQuery_stmt);
    release(&d_removeEmptyNonTerminalsFromZoneQuery_stmt);
    release(&d_insertEmptyNonTerminalQuery_stmt);
    release(&d_deleteEmptyNonTerminalQuery_stmt);
    release(&d_AddDomainKeyQuery_stmt);
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
  }

  void lookup(const QType &, const DNSName &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const DNSName &target, int domain_id, bool include_disabled=false);
  bool get(DNSResourceRecord &r);
  void getAllDomains(vector<DomainInfo> *domains, bool include_disabled=false);
  bool isMaster(const string &domain, const string &ip);
  void alsoNotifies(const string &domain, set<string> *ips);
  bool startTransaction(const string &domain, int domain_id=-1);
  bool commitTransaction();
  bool abortTransaction();
  bool feedRecord(const DNSResourceRecord &r, string *ordername=0);
  bool feedEnts(int domain_id, map<string,bool>& nonterm);
  bool feedEnts3(int domain_id, const string &domain, map<string,bool> &nonterm, unsigned int times, const string &salt, bool narrow);
  bool createDomain(const string &domain);
  bool createSlaveDomain(const string &ip, const string &domain, const string &nameserver, const string &account);
  bool deleteDomain(const string &domain);
  bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db);
  void setFresh(uint32_t domain_id);
  void getUnfreshSlaveInfos(vector<DomainInfo> *domains);
  void getUpdatedMasters(vector<DomainInfo> *updatedDomains);
  bool getDomainInfo(const string &domain, DomainInfo &di);
  void setNotified(uint32_t domain_id, uint32_t serial);
  bool setMaster(const string &domain, const string &ip);
  bool setKind(const string &domain, const DomainInfo::DomainKind kind);
  bool setAccount(const string &domain, const string &account);

  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after);
  bool updateDNSSECOrderAndAuth(uint32_t domain_id, const std::string& zonename, const std::string& qname, bool auth);
  virtual bool updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth);
  virtual bool nullifyDNSSECOrderNameAndUpdateAuth(uint32_t domain_id, const std::string& qname, bool auth);
  virtual bool nullifyDNSSECOrderNameAndAuth(uint32_t domain_id, const std::string& qname, const std::string& type);
  virtual bool setDNSSECAuthOnDsRecord(uint32_t domain_id, const std::string& qname);
  virtual bool updateEmptyNonTerminals(uint32_t domain_id, const DNSName& zonename, set<DNSName>& insert ,set<DNSName>& erase, bool remove);
  virtual bool doesDNSSEC();

  virtual bool calculateSOASerial(const string& domain, const SOAData& sd, time_t& serial);

  bool replaceRRSet(uint32_t domain_id, const string& qname, const QType& qt, const vector<DNSResourceRecord>& rrset);
  bool listSubZone(const string &zone, int domain_id);
  int addDomainKey(const string& name, const KeyData& key);
  bool getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys);
  bool getAllDomainMetadata(const string& name, std::map<std::string, std::vector<std::string> >& meta);
  bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta);
  bool setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta);
  bool clearDomainAllMetadata(const string& domain);
  
  bool removeDomainKey(const string& name, unsigned int id);
  bool activateDomainKey(const string& name, unsigned int id);
  bool deactivateDomainKey(const string& name, unsigned int id);
  
  bool getTSIGKey(const string& name, string* algorithm, string* content);
  bool setTSIGKey(const string& name, const string& algorithm, const string& content);
  bool deleteTSIGKey(const string& name);
  bool getTSIGKeys(std::vector< struct TSIGKey > &keys);

  bool listComments(const uint32_t domain_id);
  bool getComment(Comment& comment);
  void feedComment(const Comment& comment);
  bool replaceComments(const uint32_t domain_id, const string& qname, const QType& qt, const vector<Comment>& comments);

private:
  DNSName d_qname;
  SSql *d_db;
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
  string d_InsertSlaveZoneQuery;
  string d_InsertRecordQuery;
  string d_InsertEntQuery;
  string d_InsertRecordOrderQuery;
  string d_InsertEntOrderQuery;
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
  string d_setOrderAuthQuery;
  string d_nullifyOrderNameAndUpdateAuthQuery;
  string d_nullifyOrderNameAndAuthQuery;
  string d_nullifyOrderNameAndAuthENTQuery;
  string d_setAuthOnDsRecordQuery;
  string d_removeEmptyNonTerminalsFromZoneQuery;
  string d_insertEmptyNonTerminalQuery;
  string d_deleteEmptyNonTerminalQuery;

  string d_AddDomainKeyQuery;
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
  SSqlStatement* d_InsertSlaveZoneQuery_stmt;
  SSqlStatement* d_InsertRecordQuery_stmt;
  SSqlStatement* d_InsertEntQuery_stmt;
  SSqlStatement* d_InsertRecordOrderQuery_stmt;
  SSqlStatement* d_InsertEntOrderQuery_stmt;
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
  SSqlStatement* d_setOrderAuthQuery_stmt;
  SSqlStatement* d_nullifyOrderNameAndUpdateAuthQuery_stmt;
  SSqlStatement* d_nullifyOrderNameAndAuthQuery_stmt;
  SSqlStatement* d_nullifyOrderNameAndAuthENTQuery_stmt;
  SSqlStatement* d_setAuthOnDsRecordQuery_stmt;
  SSqlStatement* d_removeEmptyNonTerminalsFromZoneQuery_stmt;
  SSqlStatement* d_insertEmptyNonTerminalQuery_stmt;
  SSqlStatement* d_deleteEmptyNonTerminalQuery_stmt;
  SSqlStatement* d_AddDomainKeyQuery_stmt;
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
protected:
  bool d_dnssecQueries;
};

#endif /* PDNS_GSQLBACKEND_HH */
