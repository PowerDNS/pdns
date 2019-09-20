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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "auth-caches.hh"
#include "auth-querycache.hh"
#include "auth-packetcache.hh"
#include "utility.hh"
#include "dynhandler.hh"
#include "statbag.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include <signal.h>
#include "misc.hh"
#include "communicator.hh"
#include "dnsseckeeper.hh"
#include "nameserver.hh"
#include "responsestats.hh"
#include "ueberbackend.hh"
#include "common_startup.hh"

extern ResponseStats g_rs;

static bool s_pleasequit;
static string d_status;

bool DLQuitPlease()
{
  return s_pleasequit;
}

string DLQuitHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  string ret="No return value";
  if(parts[0]=="QUIT") {
    s_pleasequit=true;
    ret="Scheduling exit";
    g_log<<Logger::Error<<"Scheduling exit on remote request"<<endl;
  }
  return ret;
}

static void dokill(int)
{
  exit(0);
}

string DLCurrentConfigHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  return ::arg().configstring(true);
}

string DLRQuitHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  signal(SIGALRM, dokill);
  alarm(1);
  return "Exiting";
}

string DLPingHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  return "PONG";
}

string DLShowHandler(const vector<string>&parts, Utility::pid_t ppid) {
  try {
    extern StatBag S;
    string ret("Wrong number of parameters");
    if (parts.size() == 2) {
      if (parts[1] == "*")
        ret = S.directory();
      else
        ret = S.getValueStr(parts[1]);
    }

    return ret;
  }
  catch (...) {
    return "Unknown";
  }
}

void setStatus(const string &str)
{
  d_status=str;
}

string DLStatusHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  ostringstream os;
  os<<ppid<<": "<<d_status;
  return os.str();
}

string DLUptimeHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  ostringstream os;
  os<<humanDuration(time(0)-s_starttime);
  return os.str();
}

string DLPurgeHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  DNSSECKeeper dk;
  ostringstream os;
  int ret=0;

  if(parts.size()>1) {
    for (vector<string>::const_iterator i=++parts.begin();i<parts.end();++i) {
      ret+=purgeAuthCaches(*i);
      if(!boost::ends_with(*i, "$"))
	dk.clearCaches(DNSName(*i));
      else
	dk.clearAllCaches(); // at least we do what we promise.. and a bit more!
    }
  }
  else {
    ret = purgeAuthCaches();
    dk.clearAllCaches();
  }

  os<<ret;
  return os.str();
}

string DLCCHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern AuthPacketCache PC;
  extern AuthQueryCache QC;
  map<char,uint64_t> counts=QC.getCounts();
  uint64_t packetEntries = PC.size();
  ostringstream os;
  bool first=true;
  for(map<char,uint64_t>::const_iterator i=counts.begin();i!=counts.end();++i) {
    if(!first) 
      os<<", ";
    first=false;

    if(i->first=='!')
      os<<"negative queries: ";
    else if(i->first=='Q')
      os<<"queries: ";
    else 
      os<<"unknown: ";

    os<<i->second;
  }
  os<<"packets: "<<packetEntries;

  return os.str();
}

string DLQTypesHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  return g_rs.getQTypeReport();
}

string DLRSizesHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  typedef map<uint16_t, uint64_t> respsizes_t;
  respsizes_t respsizes = g_rs.getSizeResponseCounts();
  ostringstream os;
  boost::format fmt("%d\t%d\n");
  for(const respsizes_t::value_type& val :  respsizes) {
    os << (fmt % val.first % val.second).str();
  }
  return os.str();
}

string DLRemotesHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern StatBag S;
  typedef vector<pair<string, unsigned int> > totals_t;
  totals_t totals = S.getRing("remotes");
  string ret;
  boost::format fmt("%s\t%d\n");
  for(totals_t::value_type& val :  totals) {
    ret += (fmt % val.first % val.second).str();
  }
  return ret;
}

string DLSettingsHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  static const char *whitelist[]={"query-logging",0};
  const char **p;

  if(parts.size()!=3) {
    return "Syntax: set variable value";
  }
  
  for(p=whitelist;*p;p++)
    if(*p==parts[1])
      break;
  if(*p) {
    ::arg().set(parts[1])=parts[2];
    return "done";
  }
  else
    return "This setting cannot be changed at runtime, or no such setting";

}

string DLVersionHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  return VERSION;
}

string DLNotifyRetrieveHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern CommunicatorClass Communicator;
  ostringstream os;
  if(parts.size()!=2)
    return "syntax: retrieve domain";

  DNSName domain;
  try {
    domain = DNSName(parts[1]);
  } catch (...) {
    return "Failed to parse domain as valid DNS name";
  }

  DomainInfo di;
  UeberBackend B;
  if(!B.getDomainInfo(domain, di))
    return "Domain '"+domain.toString()+"' unknown";
  
  if(di.kind != DomainInfo::Slave || di.masters.empty())
    return "Domain '"+domain.toString()+"' is not a slave domain (or has no master defined)";

  random_shuffle(di.masters.begin(), di.masters.end());
  Communicator.addSuckRequest(domain, di.masters.front()); 
  return "Added retrieval request for '"+domain.toString()+"' from master "+di.masters.front().toLogString();
}

string DLNotifyHostHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern CommunicatorClass Communicator;
  ostringstream os;
  if(parts.size()!=3)
    return "syntax: notify-host domain ip";
  if(!::arg().mustDo("master") && !(::arg().mustDo("slave") && ::arg().mustDo("slave-renotify")))
      return "PowerDNS not configured as master or slave with re-notifications";

  DNSName domain;
  try {
    domain = DNSName(parts[1]);
  } catch (...) {
    return "Failed to parse domain as valid DNS name";
  }

  try {
    ComboAddress ca(parts[2]);
  } catch(...)
  {
    return "Unable to convert '"+parts[2]+"' to an IP address";
  }
  
  g_log<<Logger::Warning<<"Notification request to host "<<parts[2]<<" for domain '"<<domain<<"' received from operator"<<endl;
  Communicator.notify(domain, parts[2]);
  return "Added to queue";
}

string DLNotifyHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern CommunicatorClass Communicator;
  UeberBackend B;
  if(parts.size()!=2)
    return "syntax: notify domain";
  if(!::arg().mustDo("master") && !(::arg().mustDo("slave") && ::arg().mustDo("slave-renotify")))
      return "PowerDNS not configured as master or slave with re-notifications";
  g_log<<Logger::Warning<<"Notification request for domain '"<<parts[1]<<"' received from operator"<<endl;

  if (parts[1] == "*") {
    vector<DomainInfo> domains;
    B.getAllDomains(&domains);

    int total = 0;
    int notified = 0;
    for (const auto& di : domains) {
      if (di.kind == DomainInfo::Master || di.kind == DomainInfo::Slave) { // MASTER and Slave if slave-renotify is enabled
        total++;
        if(Communicator.notifyDomain(di.zone, &B))
          notified++;
      }
    }

    if (total != notified)
      return itoa(notified)+" out of "+itoa(total)+" zones added to queue - see log";
    return "Added "+itoa(total)+" MASTER/SLAVE zones to queue";
  } else {
    DNSName domain;
    try {
      domain = DNSName(parts[1]);
    } catch (...) {
      return "Failed to parse domain as valid DNS name";
    }
    if(!Communicator.notifyDomain(DNSName(parts[1]), &B))
      return "Failed to add to the queue - see log";
    return "Added to queue";
  }
}

string DLRediscoverHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  UeberBackend B;
  try {
    g_log<<Logger::Error<<"Rediscovery was requested"<<endl;
    string status="Ok";
    B.rediscover(&status);
    return status;
  }
  catch(PDNSException &ae) {
    return ae.reason;
  }

}

string DLReloadHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  UeberBackend B;
  B.reload();
  g_log<<Logger::Error<<"Reload was requested"<<endl;
  return "Ok";
}


string DLListZones(const vector<string>&parts, Utility::pid_t ppid)
{
  UeberBackend B;
  g_log<<Logger::Notice<<"Received request to list zones."<<endl;
  vector<DomainInfo> domains;
  B.getAllDomains(&domains);
  ostringstream ret;
  int kindFilter = -1;
  if (parts.size() > 1) {
    if (toUpper(parts[1]) == "MASTER")
      kindFilter = 0;
    else if (toUpper(parts[1]) == "SLAVE")
      kindFilter = 1;
    else if (toUpper(parts[1]) == "NATIVE")
      kindFilter = 2;
  }

  int count = 0;

  for (const auto& di: domains) {
    if (di.kind == kindFilter || kindFilter == -1) {
      ret<<di.zone.toString()<<endl;
      count++;
    }
  }
  if (kindFilter != -1)
    ret<<parts[1]<<" zonecount:"<<count;
  else
    ret<<"All zonecount:"<<count;

  return ret.str();
}

#ifdef HAVE_P11KIT1
extern bool PKCS11ModuleSlotLogin(const std::string& module, const string& tokenId, const std::string& pin);
#endif

string DLTokenLogin(const vector<string>&parts, Utility::pid_t ppid)
{
#ifndef HAVE_P11KIT1
  return "PKCS#11 support not compiled in";
#else
  if (parts.size() != 4) {
    return "invalid number of parameters, needs 4, got " + std::to_string(parts.size());
  }

  if (PKCS11ModuleSlotLogin(parts[1], parts[2], parts[3])) {
    return "logged in";
  } else {
    return "could not log in, check logs";
  }
#endif
}
