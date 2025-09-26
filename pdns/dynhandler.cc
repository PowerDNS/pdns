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
#include <csignal>
#include "misc.hh"
#include "communicator.hh"
#include "dnsseckeeper.hh"
#include "nameserver.hh"
#include "responsestats.hh"
#include "ueberbackend.hh"
#include "auth-main.hh"

extern ResponseStats g_rs;

static bool s_pleasequit;
static string d_status;

bool DLQuitPlease()
{
  return s_pleasequit;
}

string DLQuitHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
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

string DLCurrentConfigHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  if(parts.size() > 1) {
    if(parts.size() == 2 && parts[1] == "diff") {
      return ::arg().configstring(true, false);
    }
    return "Syntax: current-config [diff]";
  }
  return ::arg().configstring(true, true);
}

string DLRQuitHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
{
  signal(SIGALRM, dokill);
  alarm(1);
  return "Exiting";
}

string DLPingHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
{
  return "PONG";
}

string DLShowHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  try {
    extern StatBag S;
    string ret("Wrong number of parameters");
    if (parts.size() == 2) {
      if (parts[1] == "*")
        ret = S.directory();
      else if (parts[1].length() && parts[1][parts[1].length() - 1 ] == '*')
        ret = S.directory(parts[1].substr(0, parts[1].length() - 1));
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

string DLStatusHandler(const vector<string>& /* parts */, Utility::pid_t ppid)
{
  ostringstream os;
  os<<ppid<<": "<<d_status;
  return os.str();
}

string DLUptimeHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
{
  ostringstream os;
  os<<humanDuration(time(nullptr)-g_starttime);
  return os.str();
}

string DLPurgeHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  ostringstream os;
  int ret=0;

  if(parts.size()>1) {
    for (vector<string>::const_iterator i=++parts.begin();i<parts.end();++i) {
      g_log<<Logger::Warning<<"Cache clear request for '"<<*i<<"' received from operator"<<endl;
      ret+=purgeAuthCaches(*i);
      if(!boost::ends_with(*i, "$"))
        DNSSECKeeper::clearCaches(ZoneName(*i));
      else
        DNSSECKeeper::clearAllCaches(); // at least we do what we promise.. and a bit more!
    }
  }
  else {
    g_log<<Logger::Warning<<"Cache clear request received from operator"<<endl;
    ret = purgeAuthCaches();
    DNSSECKeeper::clearAllCaches();
  }

  os<<ret;
  return os.str();
}

string DLCCHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
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
  if(!first)
    os<<", ";
  os<<"packets: "<<packetEntries;

  return os.str();
}

string DLQTypesHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
{
  return g_rs.getQTypeReport();
}

string DLRSizesHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
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

string DLRemotesHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
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

string DLSettingsHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  static const char *whitelist[]={"query-logging",nullptr};
  const char **p;

  if(parts.size()!=3) {
    return "Syntax: set variable value";
  }

  for(p=whitelist;*p;p++)
    if(*p==parts[1])
      break;
  if(*p) {
    ::arg().set(parts[1])=parts[2];
    g_log<<Logger::Warning<<"Configuration change for setting '"<<parts[1]<<"' to value '"<<parts[2]<<"' received from operator"<<endl;
    return "done";
  }
  else
    return "This setting cannot be changed at runtime, or no such setting";

}

string DLVersionHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
{
  return VERSION;
}

string DLNotifyRetrieveHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  extern CommunicatorClass Communicator;
  ostringstream os;
  if(parts.size()!=2 && parts.size()!=3)
    return "syntax: retrieve zone [ip]";

  ZoneName domain;
  try {
    domain = ZoneName(parts[1]);
  } catch (...) {
    return "Failed to parse '" + parts[1] + "' as a valid zone name";
  }

  ComboAddress primary_ip;
  bool override_primary = false;
  if (parts.size() == 3) {
    try {
      primary_ip = ComboAddress{parts[2], 53};
    } catch (...) {
      return "Invalid primary address";
    }
    override_primary = true;
  }

  DomainInfo di;
  UeberBackend B;
  if(!B.getDomainInfo(domain, di)) {
    return " Zone '" + domain.toString() + "' unknown";
  }

  if (override_primary) {
    di.primaries.clear();
    di.primaries.push_back(primary_ip);
  }

  if (!override_primary && (!di.isSecondaryType() || di.primaries.empty()))
    return "Zone '" + domain.toString() + "' is not a secondary/consumer zone (or has no primary defined)";

  shuffle(di.primaries.begin(), di.primaries.end(), pdns::dns_random_engine());
  const auto& primary = di.primaries.front();
  Communicator.addSuckRequest(domain, primary, SuckRequest::PdnsControl, override_primary);
  g_log << Logger::Warning << "Retrieval request for zone '" << domain << "' from primary '" << primary << "' received from operator" << endl;
  return "Added retrieval request for '" + domain.toLogString() + "' from primary " + primary.toLogString();
}

string DLNotifyHostHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  extern CommunicatorClass Communicator;
  ostringstream os;
  if(parts.size()!=3)
    return "syntax: notify-host zone ip";
  if(!::arg().mustDo("primary") && !(::arg().mustDo("secondary") && ::arg().mustDo("secondary-do-renotify")))
    return "PowerDNS not configured as primary, or secondary with re-notifications";

  ZoneName domain;
  try {
    domain = ZoneName(parts[1]);
  } catch (...) {
    return "Failed to parse '" + parts[1] + "' as a valid zone name";
  }

  try {
    ComboAddress ca(parts[2]);
  } catch(...)
  {
    return "Unable to convert '"+parts[2]+"' to an IP address";
  }

  g_log << Logger::Warning << "Notification request to host " << parts[2] << " for zone '" << domain << "' received from operator" << endl;
  Communicator.notify(domain, parts[2]);
  return "Added to queue";
}

string DLNotifyHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  extern CommunicatorClass Communicator;
  UeberBackend B;
  if(parts.size()!=2)
    return "syntax: notify zone";
  if(!::arg().mustDo("primary") && !(::arg().mustDo("secondary") && ::arg().mustDo("secondary-do-renotify")))
    return "PowerDNS not configured as primary (primary), or secondary (secondary) with re-notifications";
  g_log << Logger::Warning << "Notification request for zone '" << parts[1] << "' received from operator" << endl;

  if (parts[1] == "*") {
    vector<DomainInfo> domains;
    B.getAllDomains(&domains, true, false);

    int total = 0;
    int notified = 0;
    for (const auto& di : domains) {
      if (di.kind != DomainInfo::Native) { // Primary and secondary if secondary-do-renotify is enabled
        total++;
        if(Communicator.notifyDomain(di.zone, &B))
          notified++;
      }
    }

    if (total != notified)
      return std::to_string(notified)+" out of "+std::to_string(total)+" zones added to queue - see log";
    return "Added " + std::to_string(total) + " MASTER/SLAVE/PRODUCER/CONSUMER zones to queue";
  } else {
    ZoneName domain;
    try {
      domain = ZoneName(parts[1]);
    } catch (...) {
      return "Failed to parse '" + parts[1] + "' as a valid zone name";
    }
    if(!Communicator.notifyDomain(domain, &B)) {
      return "Failed to add " + domain.toLogString() + " to the queue - see log";
    }
    return "Added " + domain.toLogString() + " to queue";
  }
}

string DLRediscoverHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
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

string DLReloadHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
{
  UeberBackend B;
  B.reload();
  g_log<<Logger::Error<<"Reload was requested"<<endl;
  return "Ok";
}

string DLListZones(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  UeberBackend B;
  g_log<<Logger::Notice<<"Received request to list zones."<<endl;
  vector<DomainInfo> domains;
  B.getAllDomains(&domains, false, false);
  ostringstream ret;
  DomainInfo::DomainKind kind;
  if (parts.size() > 1) {
    kind = DomainInfo::stringToKind(parts.at(1));
  }
  else {
    kind = DomainInfo::All;
  }

  int count = 0;

  for (const auto& di: domains) {
    if (di.kind == kind || kind == DomainInfo::All) {
      ret<<di.zone.toString()<<endl;
      count++;
    }
  }

  ret << DomainInfo::getKindString(kind) << " zonecount: " << count;

  return ret.str();
}

string DLFlushHandler(const vector<string>& /*parts*/, Utility::pid_t /*ppid*/)
{
  UeberBackend B; // NOLINT(readability-identifier-length)
  B.flush();
  g_log<<Logger::Error<<"Backend flush was requested"<<endl;
  return "Ok";
}

#ifdef HAVE_P11KIT1
extern bool PKCS11ModuleSlotLogin(const std::string& module, const string& tokenId, const std::string& pin);
#endif

string DLTokenLogin([[maybe_unused]] const vector<string>& parts, [[maybe_unused]] Utility::pid_t /* ppid */)
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

string DLSuckRequests(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
{
  string ret;
  for (auto const &d: Communicator.getSuckRequests()) {
    ret += d.first.toString() + " " + d.second.toString() + "\n";
  }
  return ret;
}
