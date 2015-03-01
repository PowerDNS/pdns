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
    if(d_db)
      delete d_db;
  }
  
  void setDB(SSql *db)
  {
    d_db=db;
    if (d_db) {
      d_db->setLog(::arg().mustDo("query-logging"));
    }
  }
  
  virtual string sqlEscape(const string &name);
  void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const string &target, int domain_id, bool include_disabled=false);
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
  virtual bool updateEmptyNonTerminals(uint32_t domain_id, const std::string& zonename, set<string>& insert ,set<string>& erase, bool remove);
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
  string d_qname;
  SSql *d_db;
  SSql::result_t d_result;

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

protected:
  bool d_dnssecQueries;
};
