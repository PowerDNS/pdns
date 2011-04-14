#ifndef MONGODB_HH
#define MONGODB_HH

#include "pdns/dnsbackend.hh"

#undef VERSION
#include <string>
using std::string;

#include "client/dbclient.h"

class MONGODBException {
public:
  MONGODBException(const string &ex) : what(ex){}
  string what;
};

class MONGODBBackend : public DNSBackend {

public:


//  MINIMAL BACKEND

    MONGODBBackend(const string &suffix="");
    ~MONGODBBackend();
    bool list(const string &target, int domain_id);
    void lookup(const QType &qtype, const string &qname, DNSPacket *p, int domain_id);
    bool get(DNSResourceRecord &rr);
    //! fills the soadata struct with the SOA details. Returns false if there is no SOA.
    bool getSOA(const string &name, SOAData &soadata, DNSPacket *p=0);


//  SLAVE BACKEND
 
    bool getDomainInfo(const string &domain, DomainInfo &di, SOAData *soadata = NULL, unsigned int domain_id = 0);
    bool isMaster(const string &name, const string &ip);
    void getUnfreshSlaveInfos(vector<DomainInfo>* domains);
    void setFresh(int id);
/*
    bool startTransaction(const string &qname, int id);
    bool commitTransaction();
    bool abortTransaction();
    bool feedRecord(const DNSResourceRecord &rr);
*/


//  SUPERMASTER BACKEND
/*
    bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db)
    bool createSlaveDomain(const string &ip, const string &domain, const string &account)
*/


//  MASTER BACKEND

    void getUpdatedMasters(vector<DomainInfo>* domains);
    void setNotifed(int id, u_int32_t serial);


//  DNSSEC BACKEND
    //! get a list of IP addresses that should also be notified for a domain
    void alsoNotifies(const string &domain, set<string> *ips);
    bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta, set<string> *ips = NULL);
    bool setDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta);

    bool getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys);
    bool removeDomainKey(const string& name, unsigned int id);
    bool activateDomainKey(const string& name, unsigned int id);
    bool deactivateDomainKey(const string& name, unsigned int id);
    bool getTSIGKey(const string& name, string* algorithm, string* content);
    int addDomainKey(const string& name, const KeyData& key);

    bool getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after);
    bool updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth);
    bool updateDNSSECOrderAndAuth(uint32_t domain_id, const std::string& zonename, const std::string& qname, bool auth);
  
 
//  OTHER
    void reload();


private:
//  FUNCTIONS TO THIS BACKEND

    //minimal.cc
    bool content(DNSResourceRecord* rr);
    
    //private.cc
    void getTheFreshOnes(vector<DomainInfo>* domains, string *type, string *f_name);
    bool checkDomainInfo(const string *domain, mongo::BSONObj *mongo_r, string *f_name, string *mongo_q, DomainInfo *di, SOAData *soadata = NULL);
    
    //dnssec.cc
    bool changeDomainKey(const string& name, unsigned int &id, bool toowhat);
    
    //crc32.cc
    int generateCRC32(const string& my_string);
    
    string mongo_db;
    string collection_domains;
    string collection_records;

    string collection_domainmetadata;
    string collection_cryptokeys;
    string collection_tsigkeys;

    mongo::DBClientConnection m_db;
    
    auto_ptr<mongo::DBClientCursor> cursor;
    
    string q_name;
    
//    long long unsigned int count;
    mongo::Query mongo_query;
    mongo::BSONObj mongo_record;
    bool elements;
    DNSResourceRecord rr_record;
    string type;
    mongo::BSONObjIterator* contents;
    
    
    string backend_name;
    pthread_t backend_pid;
    unsigned int backend_count;
    
    unsigned int default_ttl;

    bool logging;
    bool logging_cerr;
    bool logging_content;

    bool dnssec;
    bool checkindex;

    bool use_default_ttl;
    
};
#endif 
