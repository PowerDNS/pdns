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
#include "utility.hh"
#include "dynhandler.hh"
#include "statbag.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include <signal.h>
#include "misc.hh"
#include "communicator.hh"

static bool s_pleasequit;

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
    L<<Logger::Error<<"Scheduling exit on remote request"<<endl;
  }
  return ret;

}

static void dokill(int)
{
  exit(1);
}

string DLRQuitHandler(const vector<string>&parts, Utility::pid_t ppid)
{
#ifndef WIN32
  signal(SIGALRM, dokill);

  alarm(1);

#else

  if ( !PDNSService::instance()->isRunningAsService())
    GenerateConsoleCtrlEvent( CTRL_C_EVENT, 0 );
  else
    PDNSService::instance()->stop();
  
#endif // WIN32

  return "Exiting";
}

string DLPingHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  return "PONG";
}

string DLShowHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern StatBag S;
  string ret("Wrong number of parameters");
  if(parts.size()==2) {
    if(parts[1]=="*")
      ret=S.directory();
    else
      ret=S.getValueStr(parts[1]);
  }

  return ret;
}

static string d_status;

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
  extern PacketCache PC;  
  ostringstream os;
  int ret;

  if(parts.size()>1)
    ret=PC.purge(parts[1]);
  else
    ret=PC.purge();
  os<<ret;
  return os.str();
}

string DLCCHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern PacketCache PC;  
  map<char,int> counts=PC.getCounts();
  ostringstream os;
  bool first=true;
  for(map<char,int>::const_iterator i=counts.begin();i!=counts.end();++i) {
    if(!first) 
      os<<", ";
    first=false;

    if(i->first=='!')
      os<<"negative queries: ";
    else if(i->first=='Q')
      os<<"queries: ";
    else if(i->first=='n')
      os<<"non-recursive packets: ";
    else if(i->first=='r')
      os<<"recursive packets: ";
    else 
      os<<"unknown: ";

    os<<i->second;
  }

  return os.str();
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
    arg().set(parts[1])=parts[2];
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

  const string& domain=parts[1];
  DomainInfo di;
  PacketHandler P;
  if(!P.getBackend()->getDomainInfo(domain, di))
    return "Domain '"+domain+"' unknown";
  
  if(di.master.empty())
    return "Domain '"+domain+"' is not a slave domain (or has no master defined)";

  Communicator.addSuckRequest(domain,di.master);
  return "Added retrieval request for '"+domain+"' from master "+di.master;
}

string DLNotifyHostHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern CommunicatorClass Communicator;
  ostringstream os;
  if(parts.size()!=3)
    return "syntax: notify domain ip";
  L<<Logger::Warning<<"Notification request to host "<<parts[2]<<" for domain '"<<parts[1]<<"' received"<<endl;
  Communicator.notify(parts[1],parts[2]);
  return "Added to queue";
}

string DLNotifyHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  extern CommunicatorClass Communicator;
  ostringstream os;
  if(parts.size()!=2)
    return "syntax: notify domain";
  L<<Logger::Warning<<"Notification request for domain '"<<parts[1]<<"' received"<<endl;
  if(!Communicator.notifyDomain(parts[1]))
    return "Failed to add to the queue - see log";
  return "Added to queue";
}

string DLRediscoverHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  PacketHandler P;
  try {
    L<<Logger::Error<<"Rediscovery was requested"<<endl;
    string status="Ok";
    P.getBackend()->rediscover(&status);
    return status;
  }
  catch(AhuException &ae) {
    return ae.reason;
  }

}

string DLReloadHandler(const vector<string>&parts, Utility::pid_t ppid)
{
  PacketHandler P;
  P.getBackend()->reload();
  L<<Logger::Error<<"Reload was requested"<<endl;
  return "Ok";
}
