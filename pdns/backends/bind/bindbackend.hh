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

#if 0
  BBDomainInfo(const BBDomainInfo &orig) {
    d_name=orig.d_name;
    d_loaded=orig.d_loaded;
    d_rwlock=orig.d_rwlock;
    cout<<"Copied "<<(void*)d_rwlock<<"/"<<getpid()<<endl;
  }
  BBDomainInfo &operator=(const BBDomainInfo &orig) {
    d_loaded=orig.d_loaded;
    d_rwlock=orig.d_rwlock;
    cout<<"Assigned "<<(void*)d_rwlock<<"/"<<getpid()<<endl;
    return *this;
  }
#endif 

  void setCtime();

  bool current();

  bool d_loaded;
  bool d_checknow;
  time_t d_ctime;
  string d_name;
  string d_filename;
  unsigned int d_id;
  time_t d_last_check;
  string d_master;

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
    in a Bind-style zone file */
class BindBackend : public DNSBackend
{
public:
  BindBackend(const string &suffix=""); //!< Makes our connection to the database. Calls exit(1) if it fails.
  void getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains);
  bool getDomainInfo(const string &domain, DomainInfo &di);
  time_t getCtime(const string &fname);
  

  void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(int id);
  bool get(DNSResourceRecord &);

  static DNSBackend *maker();
  static set<string> s_contents;

  void setFresh(u_int32_t domain_id);

  bool startTransaction(const string &qname, int id);
  //  bool BindBackend::stopTransaction(const string &qname, int id);
  bool feedRecord(const DNSResourceRecord &r);
  bool commitTransaction();
  void insert(int id, const string &qname, const string &qtype, const string &content, int ttl, int prio);  
  void rediscover();
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

  int d_transaction_id;
  ofstream *d_of;
  handle *d_handle;
  void queueReload(BBDomainInfo *bbd);
  BBResourceRecord resourceMaker(int id, const string &qtype, const string &content, int ttl, int prio);
};
