/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2010  PowerDNS.COM BV

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
#ifndef PDNS_COMMUNICATOR_HH
#define PDNS_COMMUNICATOR_HH

#include <pthread.h>
#include <string>
#include <semaphore.h>
#include <queue>
#include <list>
#include <limits>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/sequenced_index.hpp>
using namespace boost::multi_index;

#ifndef WIN32 
# include <unistd.h>
# include <fcntl.h>
# include <netdb.h>
#endif // WIN32

#include "lock.hh"
#include "packethandler.hh"

#include "namespaces.hh"

struct SuckRequest
{
  string domain;
  string master;
  bool operator<(const SuckRequest& b) const
  {
    return tie(domain, master) < tie(b.domain, b.master);
  }
};

struct IDTag{};

typedef multi_index_container<
  SuckRequest,
  indexed_by<
    sequenced<>,
    ordered_unique<tag<IDTag>, identity<SuckRequest> >
  >
> UniQueue;

class NotificationQueue
{
public:
  void add(const string &domain, const string &ip)
  {
    NotificationRequest nr;
    nr.domain   = domain;
    nr.ip       = ip;
    nr.attempts = 0;
    nr.id       = Utility::random()%0xffff;
    nr.next     = time(0);

    d_nqueue.push_back(nr);
  }
  
  bool removeIf(const string &remote, uint16_t id, const string &domain)
  {
    for(d_nqueue_t::iterator i=d_nqueue.begin();i!=d_nqueue.end();++i) {
      //      cout<<i->id<<" "<<id<<endl;
      //cout<<i->ip<<" "<<remote<<endl;
      //cout<<i->domain<<" "<<domain<<endl;

      if(i->id==id && i->ip==remote && i->domain==domain) {
        d_nqueue.erase(i);
        return true;
      }
    }
    return false;
  }

  bool getOne(string &domain, string &ip, uint16_t *id, bool &purged)
  {
    for(d_nqueue_t::iterator i=d_nqueue.begin();i!=d_nqueue.end();++i) 
      if(i->next <= time(0)) {
        i->attempts++;
        purged=false;
        i->next=time(0)+1+(1<<i->attempts);
        domain=i->domain;
        ip=i->ip;
        *id=i->id;
        purged=false;
        if(i->attempts>4) {
          purged=true;
          d_nqueue.erase(i);
        }
        return true;
      }
    return false;
  }
  
  time_t earliest()
  {
    time_t early=std::numeric_limits<time_t>::max() - 1; 
    for(d_nqueue_t::const_iterator i=d_nqueue.begin();i!=d_nqueue.end();++i) 
      early=min(early,i->next);
    return early-time(0);
  }

private:
  struct NotificationRequest
  {
    string domain;
    string ip;
    int attempts;
    uint16_t id;
    time_t next;
  };

  typedef std::list<NotificationRequest>d_nqueue_t;
  d_nqueue_t d_nqueue;

};

/** this class contains a thread that communicates with other nameserver and does housekeeping.
    Initially, it is notified only of zones that need to be pulled in because they have been updated. */

class CommunicatorClass
{
public:
  CommunicatorClass() 
  {
    pthread_mutex_init(&d_lock,0);
    pthread_mutex_init(&d_holelock,0);

    d_tickinterval=60;
    d_masterschanged=d_slaveschanged=true;
  }
  time_t doNotifications();    
  void go();
  
  
  void drillHole(const string &domain, const string &ip);
  bool justNotified(const string &domain, const string &ip);
  void addSuckRequest(const string &domain, const string &master, bool priority=false);
  void notify(const string &domain, const string &ip);
  void mainloop();
  void retrievalLoopThread();
  static void *launchhelper(void *p)
  {
    static_cast<CommunicatorClass *>(p)->mainloop();
    return 0;
  }
  static void *retrieveLaunchhelper(void *p)
  {
    static_cast<CommunicatorClass *>(p)->retrievalLoopThread();
    return 0;
  }
  bool notifyDomain(const string &domain);
private:
  void makeNotifySocket();
  void queueNotifyDomain(const string &domain, DNSBackend *B);
  int d_nsock;
  map<pair<string,string>,time_t>d_holes;
  pthread_mutex_t d_holelock;
  void launchRetrievalThreads();
  void suck(const string &domain, const string &remote);
  void slaveRefresh(PacketHandler *P);
  void masterUpdateCheck(PacketHandler *P);
  pthread_mutex_t d_lock;
  
  UniQueue d_suckdomains;
  
  bool d_havepriosuckrequest;
  Semaphore d_suck_sem;
  Semaphore d_any_sem;
  time_t d_tickinterval;
  NotificationQueue d_nq;
  bool d_masterschanged, d_slaveschanged;
};

#endif
