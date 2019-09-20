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
#include "packetcache.hh"
#include "utility.hh"
#include "communicator.hh"
#include <set>
#include <boost/utility.hpp>
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "packethandler.hh"
#include "resolver.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include "packetcache.hh"
#include "threadname.hh"

// there can be MANY OF THESE
void CommunicatorClass::retrievalLoopThread(void)
{
  setThreadName("pdns/comm-retre");
  for(;;) {
    d_suck_sem.wait();
    SuckRequest sr;
    {
      Lock l(&d_lock);
      if(d_suckdomains.empty()) 
        continue;
        
      sr=d_suckdomains.front();
      d_suckdomains.pop_front();
    }
    suck(sr.domain, sr.master);
  }
}

void CommunicatorClass::loadArgsIntoSet(const char *listname, set<string> &listset)
{
  vector<string> parts;
  stringtok(parts, ::arg()[listname], ", \t");
  for (vector<string>::const_iterator iter = parts.begin(); iter != parts.end(); ++iter) {
    try {
      ComboAddress caIp(*iter, 53);
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

  pthread_t tid;
  pthread_create(&tid,0,&launchhelper,this); // Starts CommunicatorClass::mainloop()
  for(int n=0; n < ::arg().asNum("retrieval-threads", 1); ++n)
    pthread_create(&tid, 0, &retrieveLaunchhelper, this); // Starts CommunicatorClass::retrievalLoopThread()

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

void CommunicatorClass::mainloop(void)
{
  try {
    setThreadName("pdns/comm-main");
    signal(SIGPIPE,SIG_IGN);
    g_log<<Logger::Error<<"Master/slave communicator launching"<<endl;
    PacketHandler P;
    d_tickinterval=::arg().asNum("slave-cycle-interval");
    makeNotifySockets();

    int rc;
    time_t next, tick;

    for(;;) {
      slaveRefresh(&P);
      masterUpdateCheck(&P);
      tick=doNotifications(&P); // this processes any notification acknowledgements and actually send out our own notifications
      
      tick = min (tick, d_tickinterval); 
      
      next=time(0)+tick;

      while(time(0) < next) {
        rc=d_any_sem.tryWait();

        if(rc) {
          bool extraSlaveRefresh = false;
          Utility::sleep(1);
          {
            Lock l(&d_lock);
            if (d_tocheck.size())
              extraSlaveRefresh = true;
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

