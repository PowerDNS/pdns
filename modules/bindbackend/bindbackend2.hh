/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef PDNS_BINDBACKEND_HH
#define PDNS_BINDBACKEND_HH

#include <string>
#include <map>
#include <set>
#include <pthread.h>
#include <time.h>
#include <fstream>
#include <boost/utility.hpp>

#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index_container.hpp>
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

struct HashedTag{};

typedef multi_index_container<
  Bind2DNSRecord,
  indexed_by  <
                ordered_non_unique<identity<Bind2DNSRecord>, Bind2DNSCompare >,
                ordered_non_unique<tag<HashedTag>, member<Bind2DNSRecord, std::string, &Bind2DNSRecord::nsec3hash> >
              >
> recordstorage_t;

template <typename T>
class LookButDontTouch //  : public boost::noncopyable
{
public:
  LookButDontTouch() 
  {
    pthread_mutex_init(&d_lock, 0);
    pthread_mutex_init(&d_swaplock, 0);
  }
  LookButDontTouch(shared_ptr<T> records) : d_records(records)
  {
    pthread_mutex_init(&d_lock, 0);
    pthread_mutex_init(&d_swaplock, 0);
  }

  shared_ptr<const T> get()
  {
    shared_ptr<const T> ret;
    {
      Lock l(&d_lock);
      ret = d_records;
    }
    return ret;
  }

  shared_ptr<T> getWRITABLE()
  {
    shared_ptr<T> ret;
    {
      Lock l(&d_lock);
      ret = d_records;
    }
    return ret;
  }


  void swap(shared_ptr<T> records)
  {
    Lock l(&d_lock);
    Lock l2(&d_swaplock);
    d_records.swap(records);
  }
  pthread_mutex_t d_lock;
  pthread_mutex_t d_swaplock;
private:
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
  string d_filename; //!< full absolute filename of the zone on disk
  string d_status; //!< message describing status of a domain, for human consumption
  vector<string> d_masters;     //!< IP address of the master of this domain
  set<string> d_also_notify; //!< IP list of hosts to also notify
  LookButDontTouch<recordstorage_t> d_records;  //!< the actual records belonging to this domain
  time_t d_ctime;  //!< last known ctime of the file on disk
  time_t d_lastcheck; //!< last time domain was checked for freshness
  uint32_t d_lastnotified; //!< Last serial number we notified our slaves of
  unsigned int d_id;  //!< internal id of the domain
  mutable bool d_checknow; //!< if this domain has been flagged for a check
  bool d_loaded;  //!< if a domain is loaded

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
  void getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains);
  void getUpdatedMasters(vector<DomainInfo> *changedDomains);
  bool getDomainInfo(const DNSName &domain, DomainInfo &di);
  time_t getCtime(const string &fname);
   // DNSSEC
  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const string& qname, DNSName& unhashed, string& before, string& after);
  void lookup(const QType &, const DNSName &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const DNSName &target, int id, bool include_disabled=false);
  bool get(DNSResourceRecord &);
  void getAllDomains(vector<DomainInfo> *domains, bool include_disabled=false);

  static DNSBackend *maker();
  static pthread_mutex_t s_startup_lock;

  void setFresh(uint32_t domain_id);
  void setNotified(uint32_t id, uint32_t serial);
  bool startTransaction(const DNSName &qname, int id);
  bool feedRecord(const DNSResourceRecord &rr, string *ordername=0);
  bool commitTransaction();
  bool abortTransaction();
  void alsoNotifies(const DNSName &domain, set<string> *ips);
  bool searchRecords(const string &pattern, int maxResults, vector<DNSResourceRecord>& result);

// the DNSSEC related (getDomainMetadata has broader uses too)
  virtual bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta);
  virtual bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta);
  virtual bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta);
  virtual bool getDomainKeys(const DNSName& name, unsigned int kind, std::vector<KeyData>& keys);
  virtual bool removeDomainKey(const DNSName& name, unsigned int id);
  virtual int addDomainKey(const DNSName& name, const KeyData& key);
  virtual bool activateDomainKey(const DNSName& name, unsigned int id);
  virtual bool deactivateDomainKey(const DNSName& name, unsigned int id);
  virtual bool getTSIGKey(const DNSName& name, DNSName* algorithm, string* content);
  virtual bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content);
  virtual bool deleteTSIGKey(const DNSName& name);
  virtual bool getTSIGKeys(std::vector< struct TSIGKey > &keys);
  virtual bool doesDNSSEC();
  // end of DNSSEC 

  typedef multi_index_container < BB2DomainInfo , 
				  indexed_by < ordered_unique<member<BB2DomainInfo, unsigned int, &BB2DomainInfo::d_id> >,
					       ordered_unique<tag<NameTag>, member<BB2DomainInfo, DNSName, &BB2DomainInfo::d_name> >
					       > > state_t;
  static state_t s_state;
  static pthread_rwlock_t s_state_lock;

  void parseZoneFile(BB2DomainInfo *bbd);
  void insertRecord(BB2DomainInfo& bbd, const DNSName &qname, const QType &qtype, const string &content, int ttl, const std::string& hashed=string(), bool *auth=0);
  void rediscover(string *status=0);

  bool isMaster(const DNSName &name, const string &ip);

  // for supermaster support
  bool superMasterBackend(const string &ip, const DNSName &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db);
  static pthread_mutex_t s_supermaster_config_lock;
  bool createSlaveDomain(const string &ip, const DNSName &domain, const string &nameserver, const string &account);

private:
  void setupDNSSEC();
  void setupStatements();
  void freeStatements();
  void release(SSqlStatement**);
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
    recordstorage_t::const_iterator d_iter, d_end_iter;
    recordstorage_t::const_iterator d_qname_iter;
    recordstorage_t::const_iterator d_qname_end;
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

  SSqlStatement* d_getAllDomainMetadataQuery_stmt;
  SSqlStatement* d_getDomainMetadataQuery_stmt;
  SSqlStatement* d_deleteDomainMetadataQuery_stmt;
  SSqlStatement* d_insertDomainMetadataQuery_stmt;
  SSqlStatement* d_getDomainKeysQuery_stmt;
  SSqlStatement* d_deleteDomainKeyQuery_stmt;
  SSqlStatement* d_insertDomainKeyQuery_stmt;
  SSqlStatement* d_activateDomainKeyQuery_stmt;
  SSqlStatement* d_deactivateDomainKeyQuery_stmt;
  SSqlStatement* d_getTSIGKeyQuery_stmt;
  SSqlStatement* d_setTSIGKeyQuery_stmt;
  SSqlStatement* d_deleteTSIGKeyQuery_stmt;
  SSqlStatement* d_getTSIGKeysQuery_stmt;

  string d_transaction_tmpname;
  string d_logprefix;
  set<string> alsoNotify; //!< this is used to store the also-notify list of interested peers.
  ofstream *d_of;
  handle d_handle;
  static string s_binddirectory;                              //!< this is used to store the 'directory' setting of the bind configuration
  static int s_first;                                  //!< this is raised on construction to prevent multiple instances of us being generated
  int d_transaction_id;
  static bool s_ignore_broken_records;
  bool d_hybrid;

  BB2DomainInfo createDomainEntry(const DNSName& domain, const string &filename); //!< does not insert in s_state

  void queueReloadAndStore(unsigned int id);
  bool findBeforeAndAfterUnhashed(BB2DomainInfo& bbd, const DNSName& qname, DNSName& unhashed, string& before, string& after);
  void reload();
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
