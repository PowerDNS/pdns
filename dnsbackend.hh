/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

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
// $Id$
/* (C) 2002 POWERDNS.COM BV  */
   
#ifndef DNSBACKEND_HH
#define DNSBACKEND_HH

class DNSPacket;

#include "utility.hh"
#include <string>
#include <vector>
#include <map>
#include <sys/types.h>
#include "ahuexception.hh"
#include <set>

#ifndef WIN32
# include <sys/socket.h>
# include <dirent.h>
#endif // WIN32

#include "qtype.hh"
#include "dns.hh"
using namespace std;

  
class DNSBackend;  
struct DomainInfo
{
  uint32_t id;
  string zone;
  string master;
  uint32_t notified_serial;
  uint32_t serial;
  time_t last_check;
  enum {Master,Slave,Native} kind;
  DNSBackend *backend;
};

class DNSPacket;


//! This virtual base class defines the interface for backends for the ahudns. 
/** To create a backend, inherit from this class and implement functions for all virtual methods.
    Methods should not throw an exception if they are sure they did not find the requested data. However,
    if an error occurred which prevented them temporarily from performing a lockup, they should throw a DBException,
    which will cause the nameserver to send out a ServFail or take other evasive action. Probably only locking
    issues should lead to DBExceptions.

    More serious errors, which may indicate that the database connection is hosed, or a configuration error occurred, should
    lead to the throwing of an AhuException. This exception will fall straight through the UeberBackend and the PacketHandler
    and be caught by the Distributor, which will delete your DNSBackend instance and spawn a new one.
*/
class DNSBackend
{
public:
  //! lookup() initiates a lookup. A lookup without results should not throw!
  virtual void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1)=0; 
  virtual bool get(DNSResourceRecord &)=0; //!< retrieves one DNSResource record, returns false if no more were available
  //! Initiates a list of the specified domain
  /** Once initiated, DNSResourceRecord objects can be retrieved using get(). Should return false
      if the backend does not consider itself responsible for the id passed.
      \param domain_id ID of which a list is requested
  */
  virtual bool list(const string &target, int domain_id)=0;  

  virtual ~DNSBackend(){};

  //! fills the soadata struct with the SOA details. Returns false if there is no SOA.
  virtual bool getSOA(const string &name, SOAData &soadata, DNSPacket *p=0);

  //! returns true if master ip is master for domain name.
  virtual bool isMaster(const string &name, const string &ip)
  {
    return false;
  }
  
  //! starts the transaction for updating domain qname (FIXME: what is id?)
  virtual bool startTransaction(const string &qname, int id=-1)
  {
    return false;
  }

  //! commits the transaction started by startTransaction
  virtual bool commitTransaction()
  {
    return false;
  }

  //! aborts the transaction started by strartTransaction, should leave state unaltered
  virtual bool abortTransaction()
  {
    return false;
  }

  virtual void reload()
  {
  }

  virtual void rediscover(string* status=0)
  {
  }

  //! feeds a record to a zone, needs a call to startTransaction first
  virtual bool feedRecord(const DNSResourceRecord &rr)
  {
    return false; // no problem!
  }
  //! if this returns true, DomainInfo di contains information about the domain
  virtual bool getDomainInfo(const string &domain, DomainInfo &di)
  {
    return false;
  }
  //! slave capable backends should return a list of slaves that should be rechecked for staleness
  virtual void getUnfreshSlaveInfos(vector<DomainInfo>* domains)
  {
  }

  //! get a list of IP addresses that should also be notified for a domain
  virtual void alsoNotifies(const string &domain, set<string> *ips)
  {
  }

  //! get list of domains that have been changed since their last notification to slaves
  virtual void getUpdatedMasters(vector<DomainInfo>* domains)
  {
  }
  
  //! Called by PowerDNS to inform a backend that a domain has been checked for freshness
  virtual void setFresh(uint32_t domain_id)
  {

  }
  //! Called by PowerDNS to inform a backend that the changes in the domain have been reported to slaves
  virtual void setNotified(uint32_t id, uint32_t serial)
  {
  }

  //! Can be called to seed the getArg() function with a prefix
  void setArgPrefix(const string &prefix);

  //! determine if ip is a supermaster or a domain
  virtual bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db)
  {
    return false;
  }

  //! called by PowerDNS to create a slave record for a superMaster
  virtual bool createSlaveDomain(const string &ip, const string &domain, const string &account)
  {
    return false;
  }

protected:
  bool mustDo(const string &key);
  const string &getArg(const string &key);
  int getArgAsNum(const string &key);
  string getRemote(DNSPacket *p);
  bool getRemote(DNSPacket *p, struct sockaddr *in, Utility::socklen_t *len);

private:
  string d_prefix;
};

class BackendFactory
{
public:
  BackendFactory(const string &name) : d_name(name) {}
  virtual ~BackendFactory(){}
  virtual DNSBackend *make(const string &suffix)=0;
  virtual void declareArguments(const string &suffix=""){}
  const string &getName() const;
  
protected:
  void declare(const string &suffix, const string &param, const string &explanation, const string &value);

private:
  const string d_name;
};

class BackendMakerClass
{
public:
  void report(BackendFactory *bf);
  void launch(const string &instr);
  vector<DNSBackend *>all();
  void load(const string &module);
  int numLauncheable();
  vector<string> getModules();

private:
  void load_all();
  typedef map<string,BackendFactory *>d_repository_t;
  d_repository_t d_repository;
  vector<pair<string,string> >d_instances;
};

extern BackendMakerClass &BackendMakers();

//! Exception that can be thrown by a DNSBackend to indicate a failure
class DBException : public AhuException
{
public:
  DBException(const string &reason) : AhuException(reason){}
};


#endif
