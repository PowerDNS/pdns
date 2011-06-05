#ifndef LUABACKEND_HH
#define LUABACKEND_HH

#include "lua.hpp"

//extern "C" {
//#include "lua.h"
//#include "lualib.h"
//#include "lauxlib.h"
//}

#include "pdns/dnsbackend.hh"

#undef VERSION
#include <string>
using std::string;

//#undef L



class LUAException {
public:
  LUAException(const string &ex) : what(ex){}
  string what;
};

class LUABackend : public DNSBackend {

public:

//  MINIMAL BACKEND

    LUABackend(const string &suffix="");
    ~LUABackend();
    bool list(const string &target, int domain_id);
    void lookup(const QType &qtype, const string &qname, DNSPacket *p, int domain_id);
    bool get(DNSResourceRecord &rr);
    //! fills the soadata struct with the SOA details. Returns false if there is no SOA.
    bool getSOA(const string &name, SOAData &soadata, DNSPacket *p=0);


//  MASTER BACKEND

    void getUpdatedMasters(vector<DomainInfo>* domains);
    void setNotifed(int id, u_int32_t serial);


//  SLAVE BACKEND
 
    bool getDomainInfo(const string &domain, DomainInfo &di);
    bool isMaster(const string &name, const string &ip);
    void getUnfreshSlaveInfos(vector<DomainInfo>* domains);
    void setFresh(int id);

    bool startTransaction(const string &qname, int id);
    bool commitTransaction();
    bool abortTransaction();
    bool feedRecord(const DNSResourceRecord &rr);


//  SUPERMASTER BACKEND

    bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db);
    bool createSlaveDomain(const string &ip, const string &domain, const string &account);


//  DNSSEC BACKEND

    //! get a list of IP addresses that should also be notified for a domain
    void alsoNotifies(const string &domain, set<string> *ips);
    bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta);
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
    void rediscover(string* status=0);
    

    string backend_name;
    lua_State *lua;
    DNSPacket *dnspacket;

    //private.cc
    string my_getArg(string a);
    bool my_mustDo(string a);

private:

    pthread_t backend_pid;
    unsigned int backend_count;
    
    int f_lua_exec_error;
    
    //mininal functions....
    int f_lua_list;
    int f_lua_lookup;
    int f_lua_get;
    int f_lua_getsoa;
    
    //master functions....
    int f_lua_getupdatedmasters;
    int f_lua_setnotifed;

    //slave functions....
    int f_lua_getdomaininfo;
    int f_lua_ismaster;
    int f_lua_getunfreshslaveinfos;
    int f_lua_setfresh;

    int f_lua_starttransaction;
    int f_lua_committransaction;
    int f_lua_aborttransaction;
    int f_lua_feedrecord;

    //supermaster functions....
    int f_lua_supermasterbackend;
    int f_lua_createslavedomain;

    //rediscover
    int f_lua_rediscover;

    //dnssec
    int f_lua_alsonotifies;
    int f_lua_getdomainmetadata;
    int f_lua_setdomainmetadata;

    int f_lua_getdomainkeys;
    int f_lua_removedomainkey;
    int f_lua_activatedomainkey;
    int f_lua_deactivatedomainkey;
    int f_lua_updatedomainkey;
    int f_lua_gettsigkey;
    int f_lua_adddomainkey;

    int f_lua_getbeforeandafternamesabsolute;
    int f_lua_updatednssecorderandauthabsolute;
    int f_lua_updatednssecorderandauth;


//    int my_lua_panic (lua_State *lua);

//  FUNCTIONS TO THIS BACKEND
    bool getValueFromTable(lua_State *lua, const std::string& key, string& value);
    bool getValueFromTable(lua_State *lua, uint32_t key, string& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, time_t& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, uint32_t& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, uint16_t& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, int& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, bool& value);

    //private.cc
    bool domaininfo_from_table(DomainInfo *di);
    void domains_from_table(vector<DomainInfo>* domains, const char *f_name);
    void dnsrr_to_table(lua_State *lua, const DNSResourceRecord *rr);

    //reload.cc
    void get_lua_function(lua_State *lua, const char *name, int *function); 

    bool dnssec;

    bool logging;

    //dnssec.cc
    bool updateDomainKey(const string& name, unsigned int &id, bool toowhat);


/*
    //minimal.cc
    bool content(DNSResourceRecord* rr);
    
    void getTheFreshOnes(vector<DomainInfo>* domains, string *type, string *f_name);
    bool checkDomainInfo(const string *domain, mongo::BSONObj *mongo_r, string *f_name, string *mongo_q, DomainInfo *di, SOAData *soadata = NULL);
    
    
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
    
    
    
    unsigned int default_ttl;

    bool logging_cerr;
    bool logging_content;

    bool checkindex;

    bool use_default_ttl;
    
    bool axfr_soa;
    SOAData last_soadata;
*/    
};

#endif 
