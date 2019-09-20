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

#ifndef LUABACKEND_HH
#define LUABACKEND_HH

#include "lua.hpp"

#include "pdns/dnsbackend.hh"

#include <string>
using std::string;

#define LUABACKEND_PREFIX "lua"

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
    bool list(const DNSName &target, int domain_id, bool include_disabled=false) override;
    void lookup(const QType &qtype, const DNSName &qname, int domain_id, DNSPacket *p=nullptr) override;
    bool get(DNSResourceRecord &rr) override;
    //! fills the soadata struct with the SOA details. Returns false if there is no SOA.
    bool getSOA(const DNSName &name, SOAData &soadata) override;


//  MASTER BACKEND

    void getUpdatedMasters(vector<DomainInfo>* domains) override;
    void setNotified(uint32_t id, uint32_t serial) override;


//  SLAVE BACKEND

    bool getDomainInfo(const DNSName& domain, DomainInfo &di, bool getSerial=true) override;
    void getUnfreshSlaveInfos(vector<DomainInfo>* domains) override;
    void setFresh(uint32_t id) override;

    bool startTransaction(const DNSName &qname, int id) override;
    bool commitTransaction() override;
    bool abortTransaction() override;
    bool feedRecord(const DNSResourceRecord &rr, const DNSName &ordername, bool ordernameIsNSEC3=false) override;


//  SUPERMASTER BACKEND

    bool superMasterBackend(const string &ip, const DNSName &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db) override;
    bool createSlaveDomain(const string &ip, const DNSName &domain, const string &nameserver, const string &account) override;


//  DNSSEC BACKEND

    //! get a list of IP addresses that should also be notified for a domain
    void alsoNotifies(const DNSName &domain, set<string> *ips) override;
    bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) override;
    bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta) override;

    bool getDomainKeys(const DNSName& name, std::vector<KeyData>& keys) override ;
    bool removeDomainKey(const DNSName& name, unsigned int id) override ;
    bool activateDomainKey(const DNSName& name, unsigned int id) override ;
    bool deactivateDomainKey(const DNSName& name, unsigned int id) override ;
    bool getTSIGKey(const DNSName& name, DNSName* algorithm, string* content) override ;
    bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) override ;
    bool updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const DNSName& qname, const std::string& ordername, bool auth);
    bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;
    bool updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype=QType::ANY) override;
    bool updateDNSSECOrderAndAuth(uint32_t domain_id, const DNSName& zonename, const DNSName& qname, bool auth);


//  OTHER
    void reload() override ;
    void rediscover(string* status=0) override ;


    string backend_name;
    lua_State *lua;
    DNSPacket *dnspacket;

    //private.cc
    string my_getArg(string a);
    bool my_mustDo(string a);
    bool my_isEmpty(string a);

private:

    pthread_t backend_pid;
    unsigned int backend_count{0};

    int f_lua_exec_error;

    //minimal functions....
    int f_lua_list;
    int f_lua_lookup;
    int f_lua_get;
    int f_lua_getsoa;

    //master functions....
    int f_lua_getupdatedmasters;
    int f_lua_setnotified;

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


//  FUNCTIONS TO THIS BACKEND
    bool getValueFromTable(lua_State *lua, const std::string& key, string& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, DNSName& value);
    bool getValueFromTable(lua_State *lua, uint32_t key, string& value);
#if !(defined(__i386__) && defined(__FreeBSD__))
    bool getValueFromTable(lua_State *lua, const std::string& key, time_t& value);
#endif
    bool getValueFromTable(lua_State *lua, const std::string& key, uint32_t& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, uint16_t& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, uint8_t& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, int& value);
    bool getValueFromTable(lua_State *lua, const std::string& key, bool& value);

    //private.cc
    bool domaininfo_from_table(DomainInfo *di);
    void domains_from_table(vector<DomainInfo>* domains, const char *f_name);
    void dnsrr_to_table(lua_State *lua, const DNSResourceRecord *rr);
    bool dnsrr_from_table(lua_State *lua, DNSResourceRecord &rr);

    //reload.cc
    void get_lua_function(lua_State *lua, const char *name, int *function);

    bool dnssec;

    bool logging;

    //dnssec.cc
    bool updateDomainKey(const DNSName& name, unsigned int &id, bool toowhat);
};

#endif
