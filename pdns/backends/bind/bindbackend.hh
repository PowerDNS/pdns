/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

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

#include "huffman.hh"

#if __GNUC__ >= 3
# include <ext/hash_map>
using namespace __gnu_cxx;
#else
# include <hash_map>
#endif


using namespace std;

class BBDomainInfo
{
public:
  BBDomainInfo();

  void setCtime();

  bool current();

  bool d_loaded;
  string d_status;
  bool d_checknow;
  time_t d_ctime;
  string d_name;
  string d_filename;
  unsigned int d_id;
  time_t d_last_check;
  string d_master;
  int d_confcount;
  u_int32_t d_lastnotified;

  bool tryRLock()
  {
    //    cout<<"[trylock!] "<<(void*)d_rwlock<<"/"<<getpid()<<endl;
    return pthread_rwlock_tryrdlock(d_rwlock)!=EBUSY;
  }
  
  void unlock()
  {
    //    cout<<"[unlock] "<<(void*)d_rwlock<<"/"<<getpid()<<endl;
    pthread_rwlock_unlock(d_rwlock);
  }
  
  void lock()
  {
    //cout<<"[writelock!] "<<(void*)d_rwlock<<"/"<<getpid()<<endl;

    pthread_rwlock_wrlock(d_rwlock);
  }

  void setCheckInterval(time_t seconds);
private:
  time_t getCtime();
  time_t d_checkinterval;
  time_t d_lastcheck;
  pthread_rwlock_t *d_rwlock;
};
      


class BBResourceRecord
{
public:
  bool operator==(const BBResourceRecord &o) const
  {
    return (o.domain_id==domain_id && o.qtype==qtype && o.content==content && 
	    o.ttl==ttl && o.priority==priority);
  }
  
  const string *qnameptr; // 4
  unsigned int domain_id;  // 4
  unsigned short int qtype;             // 2
  unsigned short int priority;  // 2
  const string *content;   // 4 
  unsigned int ttl;        // 4

};

struct compare_string
{
  bool operator()(const string& s1, const string& s2) const
  {
    return s1 == s2;
  }
};

struct hash_string
{
  size_t operator()(const string& s) const
  {
    return __stl_hash_string(s.c_str());
  }
};

typedef hash_map<string,vector<BBResourceRecord>, hash_string, compare_string> cmap_t; 



/** The BindBackend is a DNSBackend that can answer DNS related questions. It looks up data
    in a Bind-style zone file 

    How this all works is quite complex and prone to change. There are a number of containers involved which,
    together, contain everything we need to know about a domain or a record.

    A domain consists of records. So, 'example.com' has 'www.example.com' as a record.

    All record names are stored in the hash_map d_qnames, with their name as index. Attached to that index
    is a vector of BBResourceRecords ('BindBackend') belonging to that qname. Each record contains a d_domainid,
    which is the ID of the domain it belongs to.

    Then there is the map called d_bbds which has as its key the Domain ID, and attached a BBDomainInfo object, which
    tells us domain metadata (place on disk, if it is a master or a slave etc).

    To allow for AXFRs, there is yet another container, the d_zone_id_map, which contains per domain_id a vector
    of pointers to vectors of BBResourceRecords. When read in sequence, these deliver all records of a domain_id.

    As there is huge repitition in the right hand side of records, many records point to the same thing (IP address, nameserver),
    a list of these is kept in s_contents, and each BBResourceRecord only contains a pointer to a record in s_contents.

    So, summarizing:
    
    class BBResourceRecord:
    Everything you need to know about a record. In this context we call the name of a BBResourceRecord 'qname'

    class BBDomainInfo:
    Domain metadata, like location on disk, last time zone was checked

    d_qnames<qname,vector<BBResourceRecord> >:
    If you know the qname of a record, this gives you all records under that name. 

    set<string>s_contents:
    Set of all 'contents' of records, the right hand sides. 

    map<int,vector<vector<BBResourceRecord>* > > d_zone_id_map:
    If you know the zone_id, this has a vector of pointers to vectors in d_qnames, for AXFR

    map<unsigned int, BBDomainInfo>d_bbds:
    Map of all domains we know about and metadata about them.

    
*/
class BindBackend : public DNSBackend
{
public:
  BindBackend(const string &suffix=""); //!< Makes our connection to the database. Calls exit(1) if it fails.
  void getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains);
  void getUpdatedMasters(vector<DomainInfo> *changedDomains);
  bool getDomainInfo(const string &domain, DomainInfo &di);
  time_t getCtime(const string &fname);
  

  void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(int id);
  bool get(DNSResourceRecord &);

  static DNSBackend *maker();
  static set<string> s_contents;
  static pthread_mutex_t s_startup_lock;

  void setFresh(u_int32_t domain_id);
  void setNotified(u_int32_t id, u_int32_t serial);
  bool startTransaction(const string &qname, int id);
  //  bool BindBackend::stopTransaction(const string &qname, int id);
  bool feedRecord(const DNSResourceRecord &r);
  bool commitTransaction();
  bool abortTransaction();
  void insert(int id, const string &qname, const string &qtype, const string &content, int ttl, int prio);  
  void rediscover(string *status=0);
  static HuffmanCodec s_hc;
private:
  class handle
  {
  public:
    bool get(DNSResourceRecord &);
    ~handle() {
      if(d_bbd)
	d_bbd->unlock();
    }
    handle();

    BindBackend *parent;

    vector<BBResourceRecord>d_records;
    vector<BBResourceRecord>::const_iterator d_iter;
    
    vector<BBResourceRecord>::const_iterator d_riter;
    vector<BBResourceRecord>::const_iterator d_rend;
    vector<vector<BBResourceRecord> *>::const_iterator d_qname_iter;
    vector<vector<BBResourceRecord> *>::const_iterator d_qname_end;

    // static map<int,vector<vector<BBResourceRecord>* > > d_zone_id_map;  
    //                vector<vector<BBResourceRecord>* >   d_zone_id_map[id]
    // iterator NAAR         vector<BBResourceRecord>*    d_zone_id_map[id].begin()

    bool d_list;
    int id;
    BBDomainInfo* d_bbd;
    string qname;
    QType qtype;
  private:
    int count;
    
    bool get_normal(DNSResourceRecord &);
    bool get_list(DNSResourceRecord &);
  };

  static cmap_t d_qnames;
  static map<int,vector<vector<BBResourceRecord>* > > d_zone_id_map;  

  static map<unsigned int, BBDomainInfo>d_bbds;
  static int s_first;

  string d_logprefix;
  int d_transaction_id;
  string d_transaction_tmpname;
  ofstream *d_of;
  handle *d_handle;
  void queueReload(BBDomainInfo *bbd);
  BBResourceRecord resourceMaker(int id, const string &qtype, const string &content, int ttl, int prio);
  static string DLReloadHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLDomStatusHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLListRejectsHandler(const vector<string>&parts, Utility::pid_t ppid);
  static string DLReloadNowHandler(const vector<string>&parts, Utility::pid_t ppid);
  void loadConfig(string *status=0);
  void nukeZoneRecords(BBDomainInfo *bbd);
};
