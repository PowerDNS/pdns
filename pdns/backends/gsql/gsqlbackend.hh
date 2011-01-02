#include <string>
#include <map>
#include "ssql.hh"

using namespace std;

/** The GSQLBackend is a DNSBackend that can answer DNS related questions. It looks up data
    in PostgreSQL */
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
  }
  
  virtual string sqlEscape(const string &name);
  void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const string &target, int domain_id);
  bool get(DNSResourceRecord &r);
  bool isMaster(const string &domain, const string &ip);

  bool startTransaction(const string &domain, int domain_id=-1);
  bool commitTransaction();
  bool abortTransaction();
  bool feedRecord(const DNSResourceRecord &r);
  bool createSlaveDomain(const string &ip, const string &domain, const string &account);
  bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db);
  void setFresh(uint32_t domain_id);
  bool checkACL(const string &acl_type, const string &key, const string &value);
  void getUnfreshSlaveInfos(vector<DomainInfo> *domains);
  void getUpdatedMasters(vector<DomainInfo> *updatedDomains);
  bool getDomainInfo(const string &domain, DomainInfo &di);
  void setNotified(uint32_t domain_id, uint32_t serial);
  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after);
  bool updateDNSSECOrderAndAuth(uint32_t domain_id, const std::string& zonename, const std::string& qname, bool auth);
  virtual bool updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth);

  int addDomainKey(const string& name, const KeyData& key);
  bool getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys);
  bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta);
  bool setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta);
private:
  string d_qname;
  QType d_qtype;
  int d_count;
  SSql *d_db;
  SSql::result_t d_result;

  string d_wildCardNoIDQuery;
  string d_noWildCardNoIDQuery;
  string d_noWildCardIDQuery;
  string d_wildCardIDQuery;
  string d_wildCardANYNoIDQuery;
  string d_noWildCardANYNoIDQuery;
  string d_noWildCardANYIDQuery;
  string d_wildCardANYIDQuery;
  string d_listQuery;
  string d_logprefix;
  
  string d_MasterOfDomainsZoneQuery;
  string d_InfoOfDomainsZoneQuery;
  string d_InfoOfAllSlaveDomainsQuery;
  string d_SuperMasterInfoQuery;
  string d_InsertSlaveZoneQuery;
  string d_InsertRecordQuery;
  string d_UpdateSerialOfZoneQuery;
  string d_UpdateLastCheckofZoneQuery;
  string d_InfoOfAllMasterDomainsQuery;
  string d_DeleteZoneQuery;		
  string d_CheckACLQuery;   
  
  string d_beforeOrderQuery;
  string d_afterOrderQuery;
  string d_setOrderAuthQuery;

  string d_AddDomainKeyQuery;
  string d_ListDomainKeysQuery;
  string d_GetDomainMetadataQuery;
  string d_ClearDomainMetadataQuery;
  string d_SetDomainMetadataQuery;
protected:  
  bool d_dnssecQueries;
};
