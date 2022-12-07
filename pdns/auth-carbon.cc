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
#include "threadname.hh"
#include "iputils.hh"
#include "sstuff.hh"
#include "arguments.hh"
#include "auth-main.hh"

#include "namespaces.hh"

void carbonDumpThread()
try
{
  setThreadName("carbonDump");
  extern StatBag S;

  string namespace_name=arg()["carbon-namespace"];
  string hostname=arg()["carbon-ourname"];
  if (hostname.empty()) {
    try {
      hostname = getCarbonHostName();
    }
    catch(const std::exception& e) {
      throw std::runtime_error(std::string("The 'carbon-ourname' setting has not been set and we are unable to determine the system's hostname: ") + e.what());
    }
  }
  string instance_name=arg()["carbon-instance"];

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
    time_t now=time(nullptr);
    for(const string& entry : entries) {
      str<<namespace_name<<'.'<<hostname<<'.'<<instance_name<<'.'<<entry<<' '<<S.read(entry)<<' '<<now<<"\r\n";
    }
    msg = str.str();

    for (const auto& carbonServer : carbonServers) {
      ComboAddress remote(carbonServer, 2003);

      try {
        Socket s(remote.sin4.sin_family, SOCK_STREAM);
        s.setNonBlocking();
        s.connect(remote, 2);

        writen2WithTimeout(s.getHandle(), msg.c_str(), msg.length(), timeval{2,0});
      } catch (runtime_error &e){
        g_log<<Logger::Warning<<"Unable to write data to carbon server at "<<remote.toStringWithPort()<<": "<<e.what()<<endl;
        continue;
      }
    }
    sleep(arg().asNum("carbon-interval"));
  }
}
catch(std::exception& e)
{
  g_log<<Logger::Error<<"Carbon thread died: "<<e.what()<<endl;
}
catch(PDNSException& e)
{
  g_log<<Logger::Error<<"Carbon thread died, PDNSException: "<<e.reason<<endl;
}
catch(...)
{
  g_log<<Logger::Error<<"Carbon thread died"<<endl;
}
