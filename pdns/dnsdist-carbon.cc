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
#include "iputils.hh"
#include "dolog.hh"
#include "sstuff.hh"

#include "namespaces.hh"
#undef L
#include "dnsdist.hh"

GlobalStateHolder<vector<CarbonConfig> > g_carbon;
static time_t s_start=time(0);
uint64_t uptimeOfProcess(const std::string& str)
{
  return time(0) - s_start;
}

void* carbonDumpThread()
try
{
  auto localCarbon = g_carbon.getLocal();
  for(int numloops=0;;++numloops) {
    if(localCarbon->empty()) {
      sleep(1);
      continue;
    }
    /* this is wrong, we use the interval of the first server
       for every single one of them */
    if(numloops) {
      const unsigned int interval = localCarbon->at(0).interval;
      sleep(interval);
    }

    for (const auto& conf : *localCarbon) {
      const auto& server = conf.server;
      std::string hostname = conf.ourname;
      if(hostname.empty()) {
        char tmp[80];
        memset(tmp, 0, sizeof(tmp));
        gethostname(tmp, sizeof(tmp));
        char *p = strchr(tmp, '.');
        if(p) *p=0;
        hostname=tmp;
        boost::replace_all(hostname, ".", "_");
      }

      try {
        Socket s(server.sin4.sin_family, SOCK_STREAM);
        s.setNonBlocking();
        s.connect(server);  // we do the connect so the attempt happens while we gather stats
        ostringstream str;
        time_t now=time(0);
        for(const auto& e : g_stats.entries) {
          str<<"dnsdist."<<hostname<<".main."<<e.first<<' ';
          if(const auto& val = boost::get<DNSDistStats::stat_t*>(&e.second))
            str<<(*val)->load();
          else if (const auto& val = boost::get<double*>(&e.second))
            str<<**val;
          else
            str<<(*boost::get<DNSDistStats::statfunction_t>(&e.second))(e.first);
          str<<' '<<now<<"\r\n";
        }
        const auto states = g_dstates.getCopy();
        for(const auto& s : states) {
          string serverName = s->getName();
          boost::replace_all(serverName, ".", "_");
          const string base = "dnsdist." + hostname + ".main.servers." + serverName + ".";
          str<<base<<"queries" << ' ' << s->queries.load() << " " << now << "\r\n";
          str<<base<<"drops" << ' ' << s->reuseds.load() << " " << now << "\r\n";
          str<<base<<"latency" << ' ' << (s->availability != DownstreamState::Availability::Down ? s->latencyUsec/1000.0 : 0) << " " << now << "\r\n";
          str<<base<<"senderrors" << ' ' << s->sendErrors.load() << " " << now << "\r\n";
          str<<base<<"outstanding" << ' ' << s->outstanding.load() << " " << now << "\r\n";
        }
        for(const auto& front : g_frontends) {
          if (front->udpFD == -1 && front->tcpFD == -1)
            continue;

          string frontName = front->local.toStringWithPort() + (front->udpFD >= 0 ? "_udp" : "_tcp");
          boost::replace_all(frontName, ".", "_");
          const string base = "dnsdist." + hostname + ".main.frontends." + frontName + ".";
          str<<base<<"queries" << ' ' << front->queries.load() << " " << now << "\r\n";
        }
        const auto localPools = g_pools.getCopy();
        for (const auto& entry : localPools) {
          string poolName = entry.first;
          boost::replace_all(poolName, ".", "_");
          if (poolName.empty()) {
            poolName = "_default_";
          }
          const string base = "dnsdist." + hostname + ".main.pools." + poolName + ".";
          const std::shared_ptr<ServerPool> pool = entry.second;
          str<<base<<"servers" << " " << pool->servers.size() << " " << now << "\r\n";
          if (pool->packetCache != nullptr) {
            const auto& cache = pool->packetCache;
            str<<base<<"cache-size" << " " << cache->getMaxEntries() << " " << now << "\r\n";
            str<<base<<"cache-entries" << " " << cache->getEntriesCount() << " " << now << "\r\n";
            str<<base<<"cache-hits" << " " << cache->getHits() << " " << now << "\r\n";
            str<<base<<"cache-misses" << " " << cache->getMisses() << " " << now << "\r\n";
            str<<base<<"cache-deferred-inserts" << " " << cache->getDeferredInserts() << " " << now << "\r\n";
            str<<base<<"cache-deferred-lookups" << " " << cache->getDeferredLookups() << " " << now << "\r\n";
            str<<base<<"cache-lookup-collisions" << " " << cache->getLookupCollisions() << " " << now << "\r\n";
            str<<base<<"cache-insert-collisions" << " " << cache->getInsertCollisions() << " " << now << "\r\n";
            str<<base<<"cache-ttl-too-shorts" << " " << cache->getTTLTooShorts() << " " << now << "\r\n";
          }
        }

        {
          WriteLock wl(&g_qcount.queryLock);
          std::string qname;
          for(auto &record: g_qcount.records) {
            qname = record.first;
            boost::replace_all(qname, ".", "_");
            str<<"dnsdist.querycount." << qname << ".queries " << record.second << " " << now << "\r\n";
          }
          g_qcount.records.clear();
        }

        const string msg = str.str();

        int ret = waitForRWData(s.getHandle(), false, 1 , 0);
        if(ret <= 0 ) {
          vinfolog("Unable to write data to carbon server on %s: %s", server.toStringWithPort(), (ret<0 ? strerror(errno) : "Timeout"));
          continue;
        }
        s.setBlocking();
        writen2(s.getHandle(), msg.c_str(), msg.size());
      }
      catch(std::exception& e) {
        warnlog("Problem sending carbon data: %s", e.what());
      }
    }
  }
  return 0;
}
catch(std::exception& e)
{
  errlog("Carbon thread died: %s", e.what());
  return 0;
}
catch(PDNSException& e)
{
  errlog("Carbon thread died, PDNSException: %s", e.reason);
  return 0;
}
catch(...)
{
  errlog("Carbon thread died");
  return 0;
}
