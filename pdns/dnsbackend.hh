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
// $Id: dnsbackend.hh,v 1.1 2002/11/27 15:18:32 ahu Exp $
/* (C) 2002 POWERDNS.COM BV  */
   
#ifndef DNSBACKEND_HH
#define DNSBACKEND_HH

class DNSPacket;

#include "utility.hh"
#include <string>
#include <vector>
#include <map>
#include <sys/types.h>
#include <set>

#ifndef WIN32
# include <sys/socket.h>
# include <dirent.h>
#endif // WIN32

#include "qtype.hh"
#include "dns.hh"
using namespace std;

/** This virtual base class defines the interface for backends for the ahudns. To create a backend,
    inherit from this class and implement functions for all virtual methods.
*/
  
class DNSBackend;  
struct DomainInfo
{
  u_int32_t id;
  string zone;
  string master;
  u_int32_t serial;
  u_int32_t notified_serial;
  time_t last_check;
  enum {Master,Slave,Native} kind;
  DNSBackend *backend;
};

class DNSPacket;
class DNSBackend
{
public:
  virtual void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1)=0; 
  virtual bool get(DNSResourceRecord &)=0;
  virtual bool list(int domain_id)=0; 

  virtual ~DNSBackend(){};

  static void reconfigure(const string &);

  virtual bool getSOA(const string &name, SOAData &soadata);

  virtual bool isMaster(const string &name, const string &ip)
  {
    return false;
  }
  
  virtual bool startTransaction(const string &qname, int id=-1)
  {
    return false;
  }

  virtual bool commitTransaction()
  {
    return false;
  }

  virtual bool abortTransaction()
  {
    return false;
  }

  virtual void reload()
  {
  }

  virtual void rediscover()
  {
  }

  virtual bool feedRecord(const DNSResourceRecord &rr)
  {
    return false; // no problem!
  }
  virtual bool getDomainInfo(const string &domain, DomainInfo &di)
  {
    return false;
  }
  virtual void getUnfreshSlaveInfos(vector<DomainInfo>* domains)
  {
  }

  virtual void alsoNotifies(const string &domain, set<string> *ips)
  {
  }
  virtual void getUpdatedMasters(vector<DomainInfo>* domains)
  {
  }
  virtual DNSBackend *getBackendAndID(const string &qdomain, u_int32_t *id)
  {
    return 0;
  }
  virtual void setFresh(u_int32_t domain_id)
  {

  }
  virtual void setNotified(u_int32_t id, u_int32_t serial)
  {
  }

  void setArgPrefix(const string &prefix);
  virtual bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db)
  {
    return false;
  }
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

class BackendException
{};

#endif
