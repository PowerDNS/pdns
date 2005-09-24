/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include <string>
#include <map>
#include <set>
#include <pthread.h>
#include <time.h>
#include <fstream>
#include <boost/shared_ptr.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>

using namespace std;
using namespace boost;


/** This struct is used within the Bind2Backend to store DNS information. 
    It is almost identical to a DNSResourceRecord, but then a bit smaller and with different sorting rules, which make sure that the SOA record comes up front.
*/
struct Bind2DNSRecord
{
  string qname;
  uint32_t ttl;
  string content;
  uint16_t qtype;
  uint16_t priority;
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
  time_t d_last_check; //!< last time domain was checked for freshness
  string d_master;     //!< IP address of the master of this domain

  uint32_t d_lastnotified; //!< Last serial number we notified our slaves of



  //! configure how often this domain should be checked for changes (on disk)
  void setCheckInterval(time_t seconds);

  shared_ptr<vector<Bind2DNSRecord> > d_records;  //!< the actual records belonging to this domain

private:
  time_t getCtime();
  time_t d_checkinterval;
  time_t d_lastcheck;
};


class Bind2Backend : public DNSBackend
{
public:
  Bind2Backend(const string &suffix=""); //!< Makes our connection to the database. Calls exit(1) if it fails.
  void getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains);
  void getUpdatedMasters(vector<DomainInfo> *changedDomains);
  bool getDomainInfo(const string &domain, DomainInfo &di);
  time_t getCtime(const string &fname);
  

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
  void insert(int id, const string &qname, const string &qtype, const string &content, int ttl, int prio);  
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
      parent=0;
      d_records.reset();
      qname.clear();

    }

    handle();

    Bind2Backend *parent;

    shared_ptr<vector<Bind2DNSRecord> > d_records;
    vector<Bind2DNSRecord>::const_iterator d_iter, d_end_iter;

    vector<Bind2DNSRecord>::const_iterator d_qname_iter;
    vector<Bind2DNSRecord>::const_iterator d_qname_end;

    bool d_list;
    int id;

    string qname;
    string domain;
    QType qtype;
  private:
    int count;
    
    bool get_normal(DNSResourceRecord &);
    bool get_list(DNSResourceRecord &);

    void operator=(const handle& ); // don't go copying this
    handle(const handle &);
  };

  typedef map<string,int> name_id_map_t;
  static name_id_map_t s_name_id_map;  //!< convert a name to a domain id

  typedef map<uint32_t, BB2DomainInfo> id_zone_map_t;
  static id_zone_map_t s_id_zone_map, s_staging_zone_map; //!< convert a domain id to a pointer to a BB2DomainInfo

  static int s_first;                                  //!< this is raised on construction to prevent multiple instances of us being generated

  static pthread_mutex_t s_zonemap_lock;               //!< lock protecting ???

  string d_binddirectory;                              //!< this is used to store the 'directory' setting of the bind configuration

  string d_logprefix;

  int d_transaction_id;
  string d_transaction_tmpname;

  ofstream *d_of;
  handle d_handle;

  void queueReload(BB2DomainInfo *bbd);

  void reload();
  static string DLDomStatusHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLListRejectsHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid);

  void loadConfig(string *status=0);
  void nukeZoneRecords(BB2DomainInfo *bbd);
};
