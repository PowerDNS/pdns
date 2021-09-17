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

#include <set>
#include <thread>
#include <boost/utility.hpp>

#include "packetcache.hh"
#include "utility.hh"
#include "communicator.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "packethandler.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include "packetcache.hh"
#include "threadname.hh"

// there can be MANY OF THESE
void CommunicatorClass::retrievalLoopThread()
{
  setThreadName("pdns/comm-retre");
  for(;;) {
    d_suck_sem.wait();
    SuckRequest sr;
    {
      auto data = d_data.lock();
      if (data->d_suckdomains.empty()) {
        continue;
      }

      auto firstItem = data->d_suckdomains.begin();
        
      sr=*firstItem;
      data->d_suckdomains.erase(firstItem);
      if (data->d_suckdomains.empty()) {
        data->d_sorthelper = 0;
      }
    }
    suck(sr.domain, sr.master, sr.force);
  }
}

void CommunicatorClass::loadArgsIntoSet(const char *listname, set<string> &listset)
{
  vector<string> parts;
  stringtok(parts, ::arg()[listname], ", \t");
  for (const auto & part : parts) {
    try {
      ComboAddress caIp(part, 53);
      listset.insert(caIp.toStringWithPort());
    }
    catch(PDNSException &e) {
      g_log<<Logger::Error<<"Unparseable IP in "<<listname<<". Error: "<<e.reason<<endl;
      _exit(1);
    }
  }
}

void CommunicatorClass::go()
{
  try {
    PacketHandler::s_allowNotifyFrom.toMasks(::arg()["allow-notify-from"] );
  }
  catch(PDNSException &e) {
    g_log<<Logger::Error<<"Unparseable IP in allow-notify-from. Error: "<<e.reason<<endl;
    _exit(1);
  }

  std::thread mainT([this](){mainloop();});
  mainT.detach();

  for(int n=0; n < ::arg().asNum("retrieval-threads", 1); ++n) {
    std::thread retrieve([this](){retrievalLoopThread();});
    retrieve.detach();
  }

  d_preventSelfNotification = ::arg().mustDo("prevent-self-notification");

  try {
    d_onlyNotify.toMasks(::arg()["only-notify"]);
  }
  catch(PDNSException &e) {
    g_log<<Logger::Error<<"Unparseable IP in only-notify. Error: "<<e.reason<<endl;
    _exit(1);
  }

  loadArgsIntoSet("also-notify", d_alsoNotify);

  loadArgsIntoSet("forward-notify", PacketHandler::s_forwardNotify);
}

void CommunicatorClass::mainloop()
{
  try {
    setThreadName("pdns/comm-main");
    signal(SIGPIPE,SIG_IGN);
    g_log<<Logger::Error<<"Primary/secondary communicator launching"<<endl;
    PacketHandler P;
    d_tickinterval=min(::arg().asNum("slave-cycle-interval"), ::arg().asNum("xfr-cycle-interval"));
    makeNotifySockets();

    int rc;
    time_t next, tick;

    for(;;) {
      slaveRefresh(&P);
      masterUpdateCheck(&P);
      tick=doNotifications(&P); // this processes any notification acknowledgements and actually send out our own notifications
      
      tick = min (tick, d_tickinterval); 
      
      next=time(nullptr)+tick;

      while(time(nullptr) < next) {
        rc=d_any_sem.tryWait();

        if(rc) {
          bool extraSlaveRefresh = false;
          Utility::sleep(1);
          {
            auto data = d_data.lock();
            if (data->d_tocheck.size()) {
              extraSlaveRefresh = true;
            }
          }
          if (extraSlaveRefresh)
            slaveRefresh(&P);
        }
        else {
          // eat up extra posts to avoid busy looping if many posts were done
          while (d_any_sem.tryWait() == 0) {
          }
          break; // something happened
        }
        // this gets executed at least once every second
        doNotifications(&P);
      }
    }
  }
  catch(PDNSException &ae) {
    g_log<<Logger::Error<<"Exiting because communicator thread died with error: "<<ae.reason<<endl;
    Utility::sleep(1);
    _exit(1);
  }
  catch(std::exception &e) {
    g_log<<Logger::Error<<"Exiting because communicator thread died with STL error: "<<e.what()<<endl;
    _exit(1);
  }
  catch( ... )
  {
    g_log << Logger::Error << "Exiting because communicator caught unknown exception." << endl;
    _exit(1);
  }
}

