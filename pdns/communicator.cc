/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation; 

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "packetcache.hh"
#include "utility.hh"
#include <errno.h>
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
#include "session.hh"
#include "packetcache.hh"
#include <boost/lexical_cast.hpp>

// #include "namespaces.hh"

void CommunicatorClass::retrievalLoopThread(void)
{
  for(;;) {
    d_suck_sem.wait();
    SuckRequest sr;
    {
      Lock l(&d_lock);
      if(d_suckdomains.empty()) 
        continue;
	
      sr=d_suckdomains.front();
    }
    try {
      suck(sr.domain,sr.master);
    }
    catch(AhuException& ae) {
      cerr<<"Error: "<<ae.reason<<endl;
    }

    {
      Lock l(&d_lock);
      domains_by_name_t& uqIndex = d_suckdomains.get<IDTag>();
      uqIndex.erase(sr);
    }
  }

}


void CommunicatorClass::go()
{
  pthread_t tid;
  pthread_create(&tid,0,&launchhelper,this); // Starts CommunicatorClass::mainloop()
  for(int n=0; n < ::arg().asNum("retrieval-threads"); ++n)
    pthread_create(&tid, 0, &retrieveLaunchhelper, this); // Starts CommunicatorClass::retrievalLoopThread()

}

void CommunicatorClass::mainloop(void)
{
  try {
#ifndef WIN32
    signal(SIGPIPE,SIG_IGN);
#endif // WIN32
    L<<Logger::Error<<"Master/slave communicator launching"<<endl;
    PacketHandler P;
    d_tickinterval=::arg().asNum("slave-cycle-interval");
    makeNotifySockets();

    int rc;
    time_t next, tick;

    for(;;) {
      slaveRefresh(&P);
      masterUpdateCheck(&P);
      tick=doNotifications(); // this processes any notification acknowledgements and actually send out our own notifications
      
      tick = min (tick, d_tickinterval); 
      
      next=time(0)+tick;

      while(time(0) < next) {
        rc=d_any_sem.tryWait();

        if(rc)
          Utility::sleep(1);
        else { 
          break; // something happened
        }
        // this gets executed at least once every second
        doNotifications();
      }
    }
  }
  catch(AhuException &ae) {
    L<<Logger::Error<<"Exiting because communicator thread died with error: "<<ae.reason<<endl;
    Utility::sleep(1);
    exit(0);
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"Exiting because communicator thread died with STL error: "<<e.what()<<endl;
    exit(0);
  }
  catch( ... )
  {
    L << Logger::Error << "Exiting because communicator caught unknown exception." << endl;
    exit( 0 );
  }
}

