/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef UEBERBACKEND_HH
#define UEBERBACKEND_HH

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <pthread.h>
#include <semaphore.h>

#ifndef WIN32
#include <sys/un.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif // WIN32
#include <boost/utility.hpp>
#include "dnspacket.hh"
#include "dnsbackend.hh"

#include "namespaces.hh"

class BackendReporter;

/** This is a very magic backend that allows us to load modules dynamically,
    and query them in order. This is persistent over all UeberBackend instantiations
    across multiple threads. 

    The UeberBackend is transparent for exceptions, which should fall straight through.
*/

class UeberBackend : public DNSBackend, public boost::noncopyable
{
public:
  UeberBackend(const string &pname="default");
  ~UeberBackend();
  typedef DNSBackend *BackendMaker(); //!< typedef for functions returning pointers to new backends

  bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db);

  /** contains BackendReporter objects, which contain maker functions and information about
      weather a module has already been reported to existing instances of the UeberBackend
  */
//  static vector<BackendReporter>backendmakers;

  /** Tracks all created UeberBackend instances for us. We use this vector to notify
      existing threads of new modules 
  */
  static vector<UeberBackend *>instances;
  static pthread_mutex_t instances_lock;

  static bool loadmodule(const string &name);

  /** Thread function that listens on our unix domain socket for commands, for example
      instructions to load new modules */
  static void *DynListener(void *);
  static void go(void);

  /** This contains all registered backends. The DynListener modifies this list for us when
      new modules are loaded */
  vector<DNSBackend*> backends; 

  void die();
  void cleanup();

  //! the very magic handle for UeberBackend questions
  class handle
  {
  public:
    bool get(DNSResourceRecord &r);
    handle();
    ~handle();

    //! The UeberBackend class where this handle belongs to
    UeberBackend *parent;
    //! The current real backend, which is answering questions
    DNSBackend *d_hinterBackend;

    //! Index of the current backend within the backends vector
    unsigned int i;

    //! DNSPacket who asked this question
    DNSPacket *pkt_p;
    string qname;
    QType qtype;
  private:

    static int instances;
  };

  void lookup(const QType &, const string &qdomain, DNSPacket *pkt_p=0,  int zoneId=-1);

  bool getSOA(const string &domain, SOAData &sd, DNSPacket *p=0);
  bool list(const string &target, int domain_id);
  bool get(DNSResourceRecord &r);
  void getAllDomains(vector<DomainInfo> *domains);

  static DNSBackend *maker(const map<string,string> &);
  static void closeDynListener();
  static void setStatus(const string &st);
  void getUnfreshSlaveInfos(vector<DomainInfo>* domains);
  void getUpdatedMasters(vector<DomainInfo>* domains);
  bool getDomainInfo(const string &domain, DomainInfo &di);
  
  int addDomainKey(const string& name, const KeyData& key);
  bool getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys);
  bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta);
  bool setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta);

  bool removeDomainKey(const string& name, unsigned int id);
  bool activateDomainKey(const string& name, unsigned int id);
  bool deactivateDomainKey(const string& name, unsigned int id);

  bool getTSIGKey(const string& name, string* algorithm, string* content);
  
  void alsoNotifies(const string &domain, set<string> *ips); 
  void rediscover(string* status=0);
  void reload();
private:
  DNSResourceRecord lastrr;
  pthread_t tid;
  handle d_handle;
  bool d_negcached;
  bool d_cached;
  struct Question
  {
    QType qtype;
    string qname;
    int zoneId;
  }d_question;
  vector<DNSResourceRecord> d_answers;
  vector<DNSResourceRecord>::const_iterator d_cachehandleiter;

  int cacheHas(const Question &q, vector<DNSResourceRecord> &rrs);
  void addNegCache(const Question &q);
  void addCache(const Question &q, const vector<DNSResourceRecord> &rrs);
  
  static pthread_mutex_t d_mut;
  static pthread_cond_t d_cond;
  static sem_t d_dynserialize;
  static bool d_go;
  static int s_s;
  static string s_status; 
  int d_ancount;
  
  bool stale;
};


/** Class used to report new backends. It stores a maker function, and a flag that indicates that 
    this module has been reported */
class BackendReporter
{
public:
  BackendReporter(UeberBackend::BackendMaker *p)
  {
    maker=p;
    reported=false;
  };
  map<string,string>d_parameters;
  UeberBackend::BackendMaker *maker; //!< function to make this backend
  bool reported; //!< if this backend has been reported to running UeberBackend threads 
private:
};

#endif
