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

#ifndef PDNS_BINDBACKEND_HH
#define PDNS_BINDBACKEND_HH

#include <string>
#include <map>
#include <set>
#include <pthread.h>
#include <time.h>
#include <fstream>
#include <mutex>
#include <boost/utility.hpp>

#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pdns/lock.hh"
#include "pdns/misc.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/namespaces.hh"
#include "pdns/backends/gsql/ssql.hh"

using namespace ::boost::multi_index;

/**
  This struct is used within the Bind2Backend to store DNS information. It is
  almost identical to a DNSResourceRecord, but then a bit smaller and with
  different sorting rules, which make sure that the SOA record comes up front.
*/

struct Bind2DNSRecord
{
  DNSName qname;
  string content;
  string nsec3hash;
  uint32_t ttl;
  uint16_t qtype;
  mutable bool auth;
  bool operator<(const Bind2DNSRecord& rhs) const
  {
    if(qname.canonCompare(rhs.qname))
      return true;
    if(rhs.qname.canonCompare(qname))
      return false;
    if(qtype==QType::SOA && rhs.qtype!=QType::SOA)
      return true;
    return tie(qtype,content, ttl) < tie(rhs.qtype, rhs.content, rhs.ttl);
  }
};

struct Bind2DNSCompare : std::less<Bind2DNSRecord> 
{ 
    using std::less<Bind2DNSRecord>::operator(); 
    // use operator< 
    bool operator() (const DNSName& a, const Bind2DNSRecord& b) const
    {return a.canonCompare(b.qname);}
    bool operator() (const Bind2DNSRecord& a, const DNSName& b) const
    {return a.qname.canonCompare(b);}
    bool operator() (const Bind2DNSRecord& a, const Bind2DNSRecord& b) const
    {return a.qname.canonCompare(b.qname);}
};

struct NSEC3Tag{};
struct UnorderedNameTag{};

typedef multi_index_container<
  Bind2DNSRecord,
  indexed_by  <
                ordered_non_unique<identity<Bind2DNSRecord>, Bind2DNSCompare >,
                hashed_non_unique<tag<UnorderedNameTag>, member<Bind2DNSRecord, DNSName, &Bind2DNSRecord::qname> >,
                ordered_non_unique<tag<NSEC3Tag>, member<Bind2DNSRecord, std::string, &Bind2DNSRecord::nsec3hash> >
              >
> recordstorage_t;

template <typename T>
class LookButDontTouch //  : public boost::noncopyable
{
public:
  LookButDontTouch()
  {
  }
  LookButDontTouch(shared_ptr<T> records) : d_records(records)
  {
  }

  shared_ptr<const T> get()
  {
    shared_ptr<const T> ret;
    {
      std::lock_guard<std::mutex> lock(s_lock);
      ret = d_records;
    }
    return ret;
  }

  shared_ptr<T> getWRITABLE()
  {
    shared_ptr<T> ret;
    {
      std::lock_guard<std::mutex> lock(s_lock);
      ret = d_records;
    }
    return ret;
  }

private:
  static std::mutex s_lock;
  shared_ptr<T> d_records;
};


/** Class which describes all metadata of a domain for storage by the Bind2Backend, and also contains a pointer to a vector of Bind2DNSRecord's */
class BB2DomainInfo
{
public:
  BB2DomainInfo();
  void setCtime();
  bool current();
  //! configure how often this domain should be checked for changes (on disk)
  void setCheckInterval(time_t seconds);

  DNSName d_name;   //!< actual name of the domain
  DomainInfo::DomainKind d_kind; //!< the kind of domain
  string d_filename; //!< full absolute filename of the zone on disk
  string d_status; //!< message describing status of a domain, for human consumption
  vector<ComboAddress> d_masters;     //!< IP address of the master of this domain
  set<string> d_also_notify; //!< IP list of hosts to also notify
  LookButDontTouch<recordstorage_t> d_records;  //!< the actual records belonging to this domain
  time_t d_ctime{0};  //!< last known ctime of the file on disk
  time_t d_lastcheck{0}; //!< last time domain was checked for freshness
  uint32_t d_lastnotified{0}; //!< Last serial number we notified our slaves of
  unsigned int d_id;  //!< internal id of the domain
  mutable bool d_checknow; //!< if this domain has been flagged for a check
  bool d_loaded;  //!< if a domain is loaded
  bool d_wasRejectedLastReload{false}; //!< if the domain was rejected during Bind2Backend::queueReloadAndStore

private:
  time_t getCtime();
  time_t d_checkinterval;
};

class SSQLite3;
class NSEC3PARAMRecordContent;

struct NameTag
{};

class Bind2Backend : public DNSBackend
{
public:
  Bind2Backend(const string &suffix="", bool loadZones=true); 
  ~Bind2Backend();
  void getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains) override;
  void getUpdatedMasters(vector<DomainInfo> *changedDomains) override;
  bool getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial=true ) override;
  time_t getCtime(const string &fname);
   // DNSSEC
  bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;
  void lookup(const QType &, const DNSName &qdomain, int zoneId, DNSPacket *p=nullptr) override;
  bool list(const DNSName &target, int id, bool include_disabled=false) override;
  bool get(DNSResourceRecord &) override;
  void getAllDomains(vector<DomainInfo> *domains, bool include_disabled=false) override;

  static DNSBackend *maker();
  static pthread_mutex_t s_startup_lock;

  void setFresh(uint32_t domain_id) override;
  void setNotified(uint32_t id, uint32_t serial) override;
  bool startTransaction(const DNSName &qname, int id) override;
  bool feedRecord(const DNSResourceRecord &rr, const DNSName &ordername, bool ordernameIsNSEC3=false) override;
  bool commitTransaction() override;
  bool abortTransaction() override;
  void alsoNotifies(const DNSName &domain, set<string> *ips) override;
  bool searchRecords(const string &pattern, int maxResults, vector<DNSResourceRecord>& result) override;

// the DNSSEC related (getDomainMetadata has broader uses too)
  bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta) override;
  bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) override;
  bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta) override;
  bool getDomainKeys(const DNSName& name, std::vector<KeyData>& keys) override;
  bool removeDomainKey(const DNSName& name, unsigned int id) override;
  bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) override;
  bool activateDomainKey(const DNSName& name, unsigned int id) override;
  bool deactivateDomainKey(const DNSName& name, unsigned int id) override;
  bool getTSIGKey(const DNSName& name, DNSName* algorithm, string* content) override;
  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content) override;
  bool deleteTSIGKey(const DNSName& name) override;
  bool getTSIGKeys(std::vector< struct TSIGKey > &keys) override;
  bool doesDNSSEC() override;
  // end of DNSSEC 

  typedef multi_index_container < BB2DomainInfo , 
				  indexed_by < ordered_unique<member<BB2DomainInfo, unsigned int, &BB2DomainInfo::d_id> >,
					       ordered_unique<tag<NameTag>, member<BB2DomainInfo, DNSName, &BB2DomainInfo::d_name> >
					       > > state_t;
  static state_t s_state;
  static pthread_rwlock_t s_state_lock;

  void parseZoneFile(BB2DomainInfo *bbd);
  void insertRecord(BB2DomainInfo& bbd, const DNSName &qname, const QType &qtype, const string &content, int ttl, const std::string& hashed=string(), bool *auth=0);
  void rediscover(string *status=0) override;


  // for supermaster support
  bool superMasterBackend(const string &ip, const DNSName &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db) override;
  static pthread_mutex_t s_supermaster_config_lock;
  bool createSlaveDomain(const string &ip, const DNSName &domain, const string &nameserver, const string &account) override;

private:
  void setupDNSSEC();
  void setupStatements();
  void freeStatements();
  static bool safeGetBBDomainInfo(int id, BB2DomainInfo* bbd);
  static void safePutBBDomainInfo(const BB2DomainInfo& bbd);
  static bool safeGetBBDomainInfo(const DNSName& name, BB2DomainInfo* bbd);
  static bool safeRemoveBBDomainInfo(const DNSName& name);
  bool GetBBDomainInfo(int id, BB2DomainInfo** bbd);
  shared_ptr<SSQLite3> d_dnssecdb;
  bool getNSEC3PARAM(const DNSName& name, NSEC3PARAMRecordContent* ns3p);
  class handle
  {
  public:
    bool get(DNSResourceRecord &);
    void reset();
    
    handle();

    shared_ptr<const recordstorage_t > d_records;
    recordstorage_t::index<UnorderedNameTag>::type::const_iterator d_iter, d_end_iter;

    recordstorage_t::const_iterator d_qname_iter, d_qname_end;

    DNSName qname;
    DNSName domain;

    int id;
    QType qtype;
    bool d_list;
    bool mustlog;

  private:
    bool get_normal(DNSResourceRecord &);
    bool get_list(DNSResourceRecord &);

    void operator=(const handle& ); // don't go copying this
    handle(const handle &);
  };

  unique_ptr<SSqlStatement> d_getAllDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_getDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_deleteDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_insertDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_getDomainKeysQuery_stmt;
  unique_ptr<SSqlStatement> d_deleteDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_insertDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_GetLastInsertedKeyIdQuery_stmt;
  unique_ptr<SSqlStatement> d_activateDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_deactivateDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_getTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_setTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_deleteTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_getTSIGKeysQuery_stmt;

  string d_transaction_tmpname;
  string d_logprefix;
  set<string> alsoNotify; //!< this is used to store the also-notify list of interested peers.
  std::unique_ptr<ofstream> d_of;
  handle d_handle;
  static string s_binddirectory;                              //!< this is used to store the 'directory' setting of the bind configuration
  static int s_first;                                  //!< this is raised on construction to prevent multiple instances of us being generated
  int d_transaction_id;
  static bool s_ignore_broken_records;
  bool d_hybrid;

  BB2DomainInfo createDomainEntry(const DNSName& domain, const string &filename); //!< does not insert in s_state

  void queueReloadAndStore(unsigned int id);
  bool findBeforeAndAfterUnhashed(BB2DomainInfo& bbd, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after);
  void reload() override;
  static string DLDomStatusHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLListRejectsHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLAddDomainHandler(const vector<string>&parts, Utility::pid_t ppid);
  static void fixupOrderAndAuth(BB2DomainInfo& bbd, bool nsec3zone, NSEC3PARAMRecordContent ns3pr);
  void doEmptyNonTerminals(BB2DomainInfo& bbd, bool nsec3zone, NSEC3PARAMRecordContent ns3pr);
  void loadConfig(string *status=0);
  static void nukeZoneRecords(BB2DomainInfo *bbd);

};

#endif /* PDNS_BINDBACKEND_HH */
