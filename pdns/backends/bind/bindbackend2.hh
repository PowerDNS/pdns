/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2010  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <string>
#include <map>
#include <set>
#include <pthread.h>
#include <time.h>
#include <fstream>
#include <boost/utility.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "misc.hh"

#include "namespaces.hh"
using namespace boost;
using namespace ::boost::multi_index;


/** This struct is used within the Bind2Backend to store DNS information. 
    It is almost identical to a DNSResourceRecord, but then a bit smaller and with different sorting rules, which make sure that the SOA record comes up front.
*/
struct Bind2DNSRecord
{
  string qname;
  string content;
  string nsec3hash;
  uint32_t ttl;
  uint16_t qtype;
  uint16_t priority;
  mutable bool auth; 
  bool operator<(const Bind2DNSRecord& rhs) const
  {
    if(qname < rhs.qname)
      return true;
    if(qname > rhs.qname)
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
    bool operator() (const std::string& a, const Bind2DNSRecord& b) const 
    {return a < b.qname;} 
    bool operator() (const Bind2DNSRecord& a, const std::string& b) const 
    {return a.qname < b;} 
    bool operator() (const Bind2DNSRecord& a, const Bind2DNSRecord& b) const
    {
      return a < b;
    }
}; 

struct HashedTag{};

typedef multi_index_container<
  Bind2DNSRecord,
  indexed_by  <
                 ordered_non_unique<identity<Bind2DNSRecord>, Bind2DNSCompare >,
                 ordered_non_unique<tag<HashedTag>, member<Bind2DNSRecord,std::string,&Bind2DNSRecord::nsec3hash> >
              >
> recordstorage_t;

/** Class which describes all metadata of a domain for storage by the Bind2Backend, and also contains a pointer to a vector of Bind2DNSRecord's */
class BB2DomainInfo
{
public:
  BB2DomainInfo();

  void setCtime();

  bool current();

  bool d_loaded;  //!< if a domain is loaded
  string d_status; //!< message describing status of a domain, for human consumtpion
  bool d_checknow; //!< if this domain has been flagged for a check
  time_t d_ctime;  //!< last known ctime of the file on disk
  string d_name;   //!< actual name of the domain
  string d_filename; //!< full absolute filename of the zone on disk
  unsigned int d_id;  //!< internal id of the domain
  time_t d_lastcheck; //!< last time domain was checked for freshness
  vector<string> d_masters;     //!< IP address of the master of this domain
  set<string> d_also_notify; //!< IP list of hosts to also notify

  uint32_t d_lastnotified; //!< Last serial number we notified our slaves of

  //! configure how often this domain should be checked for changes (on disk)
  void setCheckInterval(time_t seconds);

  shared_ptr<recordstorage_t > d_records;  //!< the actual records belonging to this domain
private:
  time_t getCtime();

  time_t d_checkinterval;
};

class Bind2Backend : public DNSBackend
{
public:
  Bind2Backend(const string &suffix=""); //!< Makes our connection to the database. Calls exit(1) if it fails.
  ~Bind2Backend();
  void getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains);
  void getUpdatedMasters(vector<DomainInfo> *changedDomains);
  bool getDomainInfo(const string &domain, DomainInfo &di);
  time_t getCtime(const string &fname);
  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after);
  void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const string &target, int id);
  bool get(DNSResourceRecord &);

  static DNSBackend *maker();
  static pthread_mutex_t s_startup_lock;

  void setFresh(uint32_t domain_id);
  void setNotified(uint32_t id, uint32_t serial);
  bool startTransaction(const string &qname, int id);
  //  bool Bind2Backend::stopTransaction(const string &qname, int id);
  bool feedRecord(const DNSResourceRecord &r);
  bool commitTransaction();
  bool abortTransaction();
  bool updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth);
  void alsoNotifies(const string &domain, set<string> *ips);

  typedef map<string, int, CIStringCompare> name_id_map_t;
  typedef map<uint32_t, BB2DomainInfo> id_zone_map_t;

  struct State : public boost::noncopyable
  {
    name_id_map_t name_id_map;  //!< convert a name to a domain id
    id_zone_map_t id_zone_map;
  };

  static void insert(shared_ptr<State> stage, int id, const string &qname, const QType &qtype, const string &content, int ttl=300, int prio=25, const std::string& hashed=string());  
  void rediscover(string *status=0);

  bool isMaster(const string &name, const string &ip);

  // for supermaster support
  bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db);
  bool createSlaveDomain(const string &ip, const string &domain, const string &account);
  
private:
  class handle
  {
  public:
    bool get(DNSResourceRecord &);
    void reset()
    {
      d_records.reset();
      qname.clear();
      mustlog=false;
    }

    handle();

    shared_ptr<recordstorage_t > d_records;
    recordstorage_t::const_iterator d_iter, d_end_iter;

    recordstorage_t::const_iterator d_qname_iter;
    recordstorage_t::const_iterator d_qname_end;

    bool d_list;
    int id;

    string qname;
    string domain;
    QType qtype;
    bool mustlog;

  private:
    bool get_normal(DNSResourceRecord &);
    bool get_list(DNSResourceRecord &);

    void operator=(const handle& ); // don't go copying this
    handle(const handle &);
  };


  static shared_ptr<State> s_state;
  static pthread_mutex_t s_state_lock;               //!< lock protecting ???
  static pthread_mutex_t s_state_swap_lock;               
  static shared_ptr<State> getState();
  static int s_first;                                  //!< this is raised on construction to prevent multiple instances of us being generated

  static string s_binddirectory;                              //!< this is used to store the 'directory' setting of the bind configuration
  string d_logprefix;

  set<string> alsoNotify; //!< this is used to store the also-notify list of interested peers.

  int d_transaction_id;
  string d_transaction_tmpname;

  ofstream *d_of;
  handle d_handle;

  static void queueReload(BB2DomainInfo *bbd);
  bool findBeforeAndAfterUnhashed(BB2DomainInfo& bbd, const std::string& qname, std::string& unhashed, std::string& before, std::string& after);
  void reload();
  static string DLDomStatusHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLListRejectsHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid);
  static void fixupAuth(shared_ptr<recordstorage_t> records);
  void loadConfig(string *status=0);
  static void nukeZoneRecords(BB2DomainInfo *bbd);
};
