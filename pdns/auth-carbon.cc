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
#include "statbag.hh"
#include "logger.hh"
#include "iputils.hh"
#include "sstuff.hh"
#include "arguments.hh"
#include "common_startup.hh"

#include "namespaces.hh"

void* carbonDumpThread(void*)
try
{
  extern StatBag S;

  string hostname=arg()["carbon-ourname"];
  if(hostname.empty()) {
    char tmp[80];
    memset(tmp, 0, sizeof(tmp));
    gethostname(tmp, sizeof(tmp));
    char *p = strchr(tmp, '.');
    if(p) *p=0;
    hostname=tmp;
    boost::replace_all(hostname, ".", "_");
  }

  vector<string> carbonServers;
  stringtok(carbonServers, arg()["carbon-server"], ", ");

  for(;;) {
    if(carbonServers.empty()) {
      sleep(1);
      continue;
    }

    string msg;
    vector<string> entries = S.getEntries();
    ostringstream str;
    time_t now=time(0);
    for(const string& entry : entries) {
      str<<"pdns."<<hostname<<".auth."<<entry<<' '<<S.read(entry)<<' '<<now<<"\r\n";
    }
    msg = str.str();

    for (const auto& carbonServer : carbonServers) {
      ComboAddress remote(carbonServer, 2003);

      try {
        Socket s(remote.sin4.sin_family, SOCK_STREAM);
        s.setNonBlocking();
        s.connect(remote, 2);

        writen2WithTimeout(s.getHandle(), msg.c_str(), msg.length(), 2);
      } catch (runtime_error &e){
        g_log<<Logger::Warning<<"Unable to write data to carbon server at "<<remote.toStringWithPort()<<": "<<e.what()<<endl;
        continue;
      }
    }
    sleep(arg().asNum("carbon-interval"));
  }
  return 0;
}
catch(std::exception& e)
{
  g_log<<Logger::Error<<"Carbon thread died: "<<e.what()<<endl;
  return 0;
}
catch(PDNSException& e)
{
  g_log<<Logger::Error<<"Carbon thread died, PDNSException: "<<e.reason<<endl;
  return 0;
}
catch(...)
{
  g_log<<Logger::Error<<"Carbon thread died"<<endl;
  return 0;
}
