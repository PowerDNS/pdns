/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2010  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

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

#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include "lock.hh"
#include "packethandler.hh"

#include "namespaces.hh"

struct SuckRequest
{
  DNSName domain;
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
typedef UniQueue::index<IDTag>::type domains_by_name_t;

class NotificationQueue
{
public:
  void add(const DNSName &domain, const string &ip)
  {
    const ComboAddress caIp(ip);

    NotificationRequest nr;
    nr.domain   = domain;
    nr.ip       = caIp.toStringWithPort();
    nr.attempts = 0;
    nr.id       = Utility::random()%0xffff;
    nr.next     = time(0);

    d_nqueue.push_back(nr);
  }

  bool removeIf(const string &remote, uint16_t id, const DNSName &domain)
  {
    ServiceTuple stRemote, stQueued;
    parseService(remote, stRemote);

    for(d_nqueue_t::iterator i=d_nqueue.begin(); i!=d_nqueue.end(); ++i) {
      parseService(i->ip, stQueued);
      if(i->id==id && stQueued.host == stRemote.host && i->domain==domain) {
        d_nqueue.erase(i);
        return true;
      }
    }
    return false;
  }

  bool getOne(DNSName &domain, string &ip, uint16_t *id, bool &purged)
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

  void dump();

private:
  struct NotificationRequest
  {
    DNSName domain;
    string ip;
    time_t next;
    int attempts;
    uint16_t id;
  };

  typedef std::list<NotificationRequest> d_nqueue_t;
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
  
  
  void drillHole(const DNSName &domain, const string &ip);
  bool justNotified(const DNSName &domain, const string &ip);
  void addSuckRequest(const DNSName &domain, const string &master);
  void addSlaveCheckRequest(const DomainInfo& di, const ComboAddress& remote);
  void addTrySuperMasterRequest(DNSPacket *p);
  void notify(const DNSName &domain, const string &ip);
  void mainloop();
  void retrievalLoopThread();
  void sendNotification(int sock, const DNSName &domain, const ComboAddress& remote, uint16_t id);

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
  bool notifyDomain(const DNSName &domain);
private:
  void makeNotifySockets();
  void queueNotifyDomain(const DNSName &domain, UeberBackend *B);
  int d_nsock4, d_nsock6;
  map<pair<DNSName,string>,time_t>d_holes;
  pthread_mutex_t d_holelock;
  void launchRetrievalThreads();
  void suck(const DNSName &domain, const string &remote);
  void slaveRefresh(PacketHandler *P);
  void masterUpdateCheck(PacketHandler *P);
  pthread_mutex_t d_lock;
  
  UniQueue d_suckdomains;
  
  Semaphore d_suck_sem;
  Semaphore d_any_sem;
  time_t d_tickinterval;
  set<DomainInfo> d_tocheck;
  vector<DNSPacket> d_potentialsupermasters;
  set<string> d_alsoNotify;
  NotificationQueue d_nq;
  NetmaskGroup d_onlyNotify;
  bool d_havepriosuckrequest;
  bool d_masterschanged, d_slaveschanged;
  bool d_preventSelfNotification;
};

#endif
