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
#include "dnsdist.hh"
#include "threadname.hh"

GlobalStateHolder<vector<CarbonConfig> > g_carbon;
static time_t s_start=time(0);
uint64_t uptimeOfProcess(const std::string& str)
{
  return time(0) - s_start;
}

void carbonDumpThread()
try
{
  setThreadName("dnsdist/carbon");
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
      const std::string& namespace_name = conf.namespace_name;
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
      const std::string& instance_name = conf.instance_name;

      try {
        Socket s(server.sin4.sin_family, SOCK_STREAM);
        s.setNonBlocking();
        s.connect(server);  // we do the connect so the attempt happens while we gather stats
        ostringstream str;
        time_t now=time(0);
        for(const auto& e : g_stats.entries) {
          str<<namespace_name<<"."<<hostname<<"."<<instance_name<<"."<<e.first<<' ';
          if(const auto& val = boost::get<DNSDistStats::stat_t*>(&e.second))
            str<<(*val)->load();
          else if (const auto& dval = boost::get<double*>(&e.second))
            str<<**dval;
          else
            str<<(*boost::get<DNSDistStats::statfunction_t>(&e.second))(e.first);
          str<<' '<<now<<"\r\n";
        }
        auto states = g_dstates.getLocal();
        for(const auto& state : *states) {
          string serverName = state->name.empty() ? (state->remote.toString() + ":" + std::to_string(state->remote.getPort())) : state->getName();
          boost::replace_all(serverName, ".", "_");
          const string base = namespace_name + "." + hostname + "." + instance_name + ".servers." + serverName + ".";
          str<<base<<"queries" << ' ' << state->queries.load() << " " << now << "\r\n";
          str<<base<<"responses" << ' ' << state->responses.load() << " " << now << "\r\n";
          str<<base<<"drops" << ' ' << state->reuseds.load() << " " << now << "\r\n";
          str<<base<<"latency" << ' ' << (state->availability != DownstreamState::Availability::Down ? state->latencyUsec/1000.0 : 0) << " " << now << "\r\n";
          str<<base<<"senderrors" << ' ' << state->sendErrors.load() << " " << now << "\r\n";
          str<<base<<"outstanding" << ' ' << state->outstanding.load() << " " << now << "\r\n";
          str<<base<<"tcpdiedsendingquery" << ' '<< state->tcpDiedSendingQuery.load() << " " << now << "\r\n";
          str<<base<<"tcpdiedreaddingresponse" << ' '<< state->tcpDiedReadingResponse.load() << " " << now << "\r\n";
          str<<base<<"tcpgaveup" << ' '<< state->tcpGaveUp.load() << " " << now << "\r\n";
          str<<base<<"tcpreadimeouts" << ' '<< state->tcpReadTimeouts.load() << " " << now << "\r\n";
          str<<base<<"tcpwritetimeouts" << ' '<< state->tcpWriteTimeouts.load() << " " << now << "\r\n";
          str<<base<<"tcpcurrentconnections" << ' '<< state->tcpCurrentConnections.load() << " " << now << "\r\n";
          str<<base<<"tcpavgqueriesperconnection" << ' '<< state->tcpAvgQueriesPerConnection.load() << " " << now << "\r\n";
          str<<base<<"tcpavgconnectionduration" << ' '<< state->tcpAvgConnectionDuration.load() << " " << now << "\r\n";
        }

        std::map<std::string,uint64_t> frontendDuplicates;
        for(const auto& front : g_frontends) {
          if (front->udpFD == -1 && front->tcpFD == -1)
            continue;

          string frontName = front->local.toString() + ":" + std::to_string(front->local.getPort()) +  (front->udpFD >= 0 ? "_udp" : "_tcp");
          boost::replace_all(frontName, ".", "_");
          auto dupPair = frontendDuplicates.insert({frontName, 1});
          if (!dupPair.second) {
            frontName = frontName + "_" + std::to_string(dupPair.first->second);
            ++(dupPair.first->second);
          }

          const string base = namespace_name + "." + hostname + "." + instance_name + ".frontends." + frontName + ".";
          str<<base<<"queries" << ' ' << front->queries.load() << " " << now << "\r\n";
          str<<base<<"responses" << ' ' << front->responses.load() << " " << now << "\r\n";
          str<<base<<"tcpdiedreadingquery" << ' '<< front->tcpDiedReadingQuery.load() << " " << now << "\r\n";
          str<<base<<"tcpdiedsendingresponse" << ' '<< front->tcpDiedSendingResponse.load() << " " << now << "\r\n";
          str<<base<<"tcpgaveup" << ' '<< front->tcpGaveUp.load() << " " << now << "\r\n";
          str<<base<<"tcpclientimeouts" << ' '<< front->tcpClientTimeouts.load() << " " << now << "\r\n";
          str<<base<<"tcpdownstreamtimeouts" << ' '<< front->tcpDownstreamTimeouts.load() << " " << now << "\r\n";
          str<<base<<"tcpcurrentconnections" << ' '<< front->tcpCurrentConnections.load() << " " << now << "\r\n";
          str<<base<<"tcpavgqueriesperconnection" << ' '<< front->tcpAvgQueriesPerConnection.load() << " " << now << "\r\n";
          str<<base<<"tcpavgconnectionduration" << ' '<< front->tcpAvgConnectionDuration.load() << " " << now << "\r\n";
          str<<base<<"tls10-queries" << ' ' << front->tls10queries.load() << " " << now << "\r\n";
          str<<base<<"tls11-queries" << ' ' << front->tls11queries.load() << " " << now << "\r\n";
          str<<base<<"tls12-queries" << ' ' << front->tls12queries.load() << " " << now << "\r\n";
          str<<base<<"tls13-queries" << ' ' << front->tls13queries.load() << " " << now << "\r\n";
          str<<base<<"tls-unknown-queries" << ' ' << front->tlsUnknownqueries.load() << " " << now << "\r\n";
          str<<base<<"tlsnewsessions" << ' ' << front->tlsNewSessions.load() << " " << now << "\r\n";
          str<<base<<"tlsresumptions" << ' ' << front->tlsResumptions.load() << " " << now << "\r\n";
          str<<base<<"tlsunknownticketkeys" << ' ' << front->tlsUnknownTicketKey.load() << " " << now << "\r\n";
          str<<base<<"tlsinactiveticketkeys" << ' ' << front->tlsInactiveTicketKey.load() << " " << now << "\r\n";
          const TLSErrorCounters* errorCounters = nullptr;
          if (front->tlsFrontend != nullptr) {
            errorCounters = &front->tlsFrontend->d_tlsCounters;
          }
          else if (front->dohFrontend != nullptr) {
            errorCounters = &front->dohFrontend->d_tlsCounters;
          }
          if (errorCounters != nullptr) {
            str<<base<<"tlsdhkeytoosmall" << ' ' << errorCounters->d_dhKeyTooSmall << " " << now << "\r\n";
            str<<base<<"tlsinappropriatefallback" << ' ' << errorCounters->d_inappropriateFallBack << " " << now << "\r\n";
            str<<base<<"tlsnosharedcipher" << ' ' << errorCounters->d_noSharedCipher << " " << now << "\r\n";
            str<<base<<"tlsunknownciphertype" << ' ' << errorCounters->d_unknownCipherType << " " << now << "\r\n";
            str<<base<<"tlsunknownkeyexchangetype" << ' ' << errorCounters->d_unknownKeyExchangeType << " " << now << "\r\n";
            str<<base<<"tlsunknownprotocol" << ' ' << errorCounters->d_unknownProtocol << " " << now << "\r\n";
            str<<base<<"tlsunsupportedec" << ' ' << errorCounters->d_unsupportedEC << " " << now << "\r\n";
            str<<base<<"tlsunsupportedprotocol" << ' ' << errorCounters->d_unsupportedProtocol << " " << now << "\r\n";
          }
        }

        auto localPools = g_pools.getLocal();
        for (const auto& entry : *localPools) {
          string poolName = entry.first;
          boost::replace_all(poolName, ".", "_");
          if (poolName.empty()) {
            poolName = "_default_";
          }
          const string base = namespace_name + "." + hostname + "." + instance_name + ".pools." + poolName + ".";
          const std::shared_ptr<ServerPool> pool = entry.second;
          str<<base<<"servers" << " " << pool->countServers(false) << " " << now << "\r\n";
          str<<base<<"servers-up" << " " << pool->countServers(true) << " " << now << "\r\n";
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

#ifdef HAVE_DNS_OVER_HTTPS
        {
          std::map<std::string,uint64_t> dohFrontendDuplicates;
          const string base = "dnsdist." + hostname + ".main.doh.";
          for(const auto& doh : g_dohlocals) {
            string name = doh->d_local.toStringWithPort();
            boost::replace_all(name, ".", "_");
            boost::replace_all(name, ":", "_");
            boost::replace_all(name, "[", "_");
            boost::replace_all(name, "]", "_");

            auto dupPair = dohFrontendDuplicates.insert({name, 1});
            if (!dupPair.second) {
              name = name + "_" + std::to_string(dupPair.first->second);
              ++(dupPair.first->second);
            }

            vector<pair<const char*, const std::atomic<uint64_t>&>> v{
              {"http-connects", doh->d_httpconnects},
              {"http1-queries", doh->d_http1Stats.d_nbQueries},
              {"http2-queries", doh->d_http2Stats.d_nbQueries},
              {"http1-200-responses", doh->d_http1Stats.d_nb200Responses},
              {"http2-200-responses", doh->d_http2Stats.d_nb200Responses},
              {"http1-400-responses", doh->d_http1Stats.d_nb400Responses},
              {"http2-400-responses", doh->d_http2Stats.d_nb400Responses},
              {"http1-403-responses", doh->d_http1Stats.d_nb403Responses},
              {"http2-403-responses", doh->d_http2Stats.d_nb403Responses},
              {"http1-500-responses", doh->d_http1Stats.d_nb500Responses},
              {"http2-500-responses", doh->d_http2Stats.d_nb500Responses},
              {"http1-502-responses", doh->d_http1Stats.d_nb502Responses},
              {"http2-502-responses", doh->d_http2Stats.d_nb502Responses},
              {"http1-other-responses", doh->d_http1Stats.d_nbOtherResponses},
              {"http2-other-responses", doh->d_http2Stats.d_nbOtherResponses},
              {"get-queries", doh->d_getqueries},
              {"post-queries", doh->d_postqueries},
              {"bad-requests", doh->d_badrequests},
              {"error-responses", doh->d_errorresponses},
              {"redirect-responses", doh->d_redirectresponses},
              {"valid-responses", doh->d_validresponses}
            };

            for(const auto& item : v) {
              str<<base<<name<<"."<<item.first << " " << item.second << " " << now <<"\r\n";
            }
          }
        }
#endif /* HAVE_DNS_OVER_HTTPS */

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
          vinfolog("Unable to write data to carbon server on %s: %s", server.toStringWithPort(), (ret<0 ? stringerror() : "Timeout"));
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
}
catch(std::exception& e)
{
  errlog("Carbon thread died: %s", e.what());
}
catch(PDNSException& e)
{
  errlog("Carbon thread died, PDNSException: %s", e.reason);
}
catch(...)
{
  errlog("Carbon thread died");
}
