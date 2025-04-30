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
#pragma once
#include <pthread.h>
#include <string>
#include <semaphore.h>
#include <queue>
#include <list>
#include <limits>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <utility>
using namespace boost::multi_index;

#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include "lock.hh"
#include "packethandler.hh"

#include "namespaces.hh"
#include "dns_random.hh"

struct SuckRequest
{
  ZoneName domain;
  ComboAddress primary;
  bool force;
  enum RequestPriority : uint8_t
  {
    PdnsControl,
    Api,
    Notify,
    SerialRefresh,
    SignaturesRefresh
  };
  std::pair<RequestPriority, uint64_t> priorityAndOrder;
  bool operator<(const SuckRequest& b) const
  {
    return std::tie(domain, primary) < std::tie(b.domain, b.primary);
  }
};

struct IDTag
{
};

using UniQueue = multi_index_container<
  SuckRequest,
  indexed_by<
    ordered_unique<member<SuckRequest, std::pair<SuckRequest::RequestPriority, uint64_t>, &SuckRequest::priorityAndOrder>>,
    ordered_unique<tag<IDTag>, identity<SuckRequest>>>>;
using domains_by_name_t = UniQueue::index<IDTag>::type;

class NotificationQueue
{
public:
  void add(const ZoneName& domain, const string& ipstring, time_t delay = 0)
  {
    const ComboAddress ipaddress(ipstring);
    add(domain, ipaddress, delay);
  }

  void add(const ZoneName& domain, const ComboAddress& ipaddress, time_t delay = 0)
  {
    NotificationRequest nr;
    nr.domain = domain;
    nr.ip = ipaddress.toStringWithPort();
    nr.attempts = 0;
    nr.id = dns_random_uint16();
    nr.next = time(nullptr) + delay;

    d_nqueue.push_back(std::move(nr));
  }

  bool removeIf(const ComboAddress& remote, uint16_t id, const ZoneName& domain)
  {
    for (auto i = d_nqueue.begin(); i != d_nqueue.end(); ++i) {
      ComboAddress stQueued{i->ip};
      if (i->id == id && stQueued == remote && i->domain == domain) {
        d_nqueue.erase(i);
        return true;
      }
    }
    return false;
  }

  bool getOne(ZoneName& domain, string& ip, uint16_t* id, bool& purged)
  {
    for (d_nqueue_t::iterator i = d_nqueue.begin(); i != d_nqueue.end(); ++i)
      if (i->next <= time(nullptr)) {
        i->attempts++;
        purged = false;
        i->next = time(nullptr) + 1 + (1 << i->attempts);
        domain = i->domain;
        ip = i->ip;
        *id = i->id;
        purged = false;
        if (i->attempts > 4) {
          purged = true;
          d_nqueue.erase(i);
        }
        return true;
      }
    return false;
  }

  time_t earliest()
  {
    time_t early = std::numeric_limits<time_t>::max() - 1;
    for (d_nqueue_t::const_iterator i = d_nqueue.begin(); i != d_nqueue.end(); ++i)
      early = min(early, i->next);
    return early - time(nullptr);
  }

  void dump();

private:
  struct NotificationRequest
  {
    ZoneName domain;
    string ip;
    time_t next;
    int attempts;
    uint16_t id;
  };

  using d_nqueue_t = std::list<NotificationRequest>;
  d_nqueue_t d_nqueue;
};

struct ZoneStatus;

/** this class contains a thread that communicates with other nameserver and does housekeeping.
    Initially, it is notified only of zones that need to be pulled in because they have been updated. */

class CommunicatorClass
{
public:
  CommunicatorClass()
  {
    d_tickinterval = 60;
    d_secondarieschanged = true;
    d_nsock4 = -1;
    d_nsock6 = -1;
    d_preventSelfNotification = false;
  }
  time_t doNotifications(PacketHandler* P);
  void go();

  void drillHole(const ZoneName& domain, const string& ipAddress);
  bool justNotified(const ZoneName& domain, const string& ipAddress);
  void addSuckRequest(const ZoneName& domain, const ComboAddress& primary, SuckRequest::RequestPriority, bool force = false);
  void addSecondaryCheckRequest(const DomainInfo& di, const ComboAddress& remote);
  void addTryAutoPrimaryRequest(const DNSPacket& p);
  void notify(const ZoneName& domain, const string& ipAddress);
  void mainloop();
  void retrievalLoopThread();
  static void sendNotification(int sock, const ZoneName& domain, const ComboAddress& remote, uint16_t notificationId, UeberBackend* ueber);
  bool notifyDomain(const ZoneName& domain, UeberBackend* ueber);
  vector<pair<ZoneName, ComboAddress>> getSuckRequests();
  size_t getSuckRequestsWaiting();

private:
  static void loadArgsIntoSet(const char* listname, set<string>& listset);
  void makeNotifySockets();
  void queueNotifyDomain(const DomainInfo& di, UeberBackend* B);
  int d_nsock4, d_nsock6;
  LockGuarded<map<pair<ZoneName, string>, time_t>> d_holes;

  void suck(const ZoneName& domain, const ComboAddress& remote, bool force = false);
  static void ixfrSuck(const ZoneName& domain, const TSIGTriplet& tsig, const ComboAddress& laddr, const ComboAddress& remote, ZoneStatus& status, vector<DNSRecord>* axfr);

  void secondaryRefresh(PacketHandler* P);
  void primaryUpdateCheck(PacketHandler* P);
  void getUpdatedProducers(UeberBackend* B, vector<DomainInfo>& domains, const std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes);

  Semaphore d_suck_sem;
  Semaphore d_any_sem;

  set<string> d_alsoNotify;
  NetmaskGroup d_onlyNotify;
  NotificationQueue d_nq;

  time_t d_tickinterval;
  bool d_secondarieschanged;
  bool d_preventSelfNotification;
  time_t d_delayNotifications{0};

  struct Data
  {
    uint64_t d_sorthelper{0};
    UniQueue d_suckdomains;
    set<ZoneName> d_inprogress;

    set<DomainInfo> d_tocheck;
    struct cmp
    {
      bool operator()(const DNSPacket& a, const DNSPacket& b) const
      {
        return a.qdomain < b.qdomain;
      };
    };

    std::set<DNSPacket, cmp> d_potentialautoprimaries;

    // Used to keep some state on domains that failed their freshness checks.
    // uint64_t == counter of the number of failures (increased by 1 every consecutive slave-cycle-interval that the domain fails)
    // time_t == wait at least until this time before attempting a new check
    map<ZoneName, pair<uint64_t, time_t>> d_failedSecondaryRefresh;
  };

  LockGuarded<Data> d_data;

  struct RemoveSentinel
  {
    explicit RemoveSentinel(ZoneName dn, CommunicatorClass* cc) :
      d_dn(std::move(dn)), d_cc(cc)
    {}

    ~RemoveSentinel()
    {
      try {
        d_cc->d_data.lock()->d_inprogress.erase(d_dn);
      }
      catch (...) {
      }
    }
    ZoneName d_dn;
    CommunicatorClass* d_cc;
  };
};

// class that one day might be more than a function to help you get IP addresses for a nameserver
class FindNS
{
public:
  vector<string> lookup(const DNSName& name, UeberBackend* b)
  {
    vector<string> addresses;

    this->resolve_name(&addresses, name);

    if (b) {
      b->lookup(QType(QType::ANY), name, -1);
      DNSZoneRecord rr;
      while (b->get(rr))
        if (rr.dr.d_type == QType::A || rr.dr.d_type == QType::AAAA)
          addresses.push_back(rr.dr.getContent()->getZoneRepresentation()); // SOL if you have a CNAME for an NS
    }
    return addresses;
  }

private:
  void resolve_name(vector<string>* addresses, const DNSName& name)
  {
    struct addrinfo* res;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM; // otherwise we get everything in triplicate (!)
    for (int n = 0; n < 2; ++n) {
      hints.ai_family = n ? AF_INET : AF_INET6;
      ComboAddress remote;
      remote.sin4.sin_family = AF_INET6;
      if (!getaddrinfo(name.toString().c_str(), 0, &hints, &res)) {
        struct addrinfo* address = res;
        do {
          if (address->ai_addrlen <= sizeof(remote)) {
            remote.setSockaddr(address->ai_addr, address->ai_addrlen);
            addresses->push_back(remote.toString());
          }
        } while ((address = address->ai_next));
        freeaddrinfo(res);
      }
    }
  }
};
