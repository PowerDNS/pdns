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

#include "dnspacket.hh"
#include "dnsbackend.hh"

using namespace std;

class BackendReporter;

/** This is a very magic backend that allows us to load modules dynamically,
    and query them in order. This is persistent over all UeberBackend instantiations
    across multiple threads. 

    The UeberBackend is transparent for exceptions, which should fall straight through.
*/

class UeberBackend : public DNSBackend
{
public:
  UeberBackend();
  UeberBackend(const string &);
  ~UeberBackend();
  typedef DNSBackend *BackendMaker(); //!< typedef for functions returning pointers to new backends

  bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db);

  /** contains BackendReporter objects, which contain maker functions and information about
      weather a module has already been reported to existing instances of the UeberBackend
  */
  static vector<BackendReporter>backendmakers;

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
  vector<DNSBackend*>backends; 

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

  bool getSOA(const string &domain, SOAData &sd);
  bool list(int domain_id);
  bool get(DNSResourceRecord &r);

  static DNSBackend *maker(const map<string,string> &);
  static void closeDynListener();
  static void UeberBackend::setStatus(const string &st);
  void getUnfreshSlaveInfos(vector<DomainInfo>* domains);
  void getUpdatedMasters(vector<DomainInfo>* domains);
  bool getDomainInfo(const string &domain, DomainInfo &di);
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
  DNSResourceRecord d_answer;

  int cacheHas(const Question &q, DNSResourceRecord &rr);
  void addNegCache(const Question &q);
  void addOneCache(const Question &q, const DNSResourceRecord &rr);
  
  static pthread_mutex_t d_mut;
  static pthread_cond_t d_cond;
  static sem_t d_dynserialize;
  static bool d_go;
  static int s_s;
  static string s_status; 
  int d_ancount;
  static string programname;
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
