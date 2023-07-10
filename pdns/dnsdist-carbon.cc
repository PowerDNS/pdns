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

#include "dnsdist-carbon.hh"
#include "dnsdist.hh"
#include "dnsdist-backoff.hh"

#ifndef DISABLE_CARBON
#include "dolog.hh"
#include "sstuff.hh"
#include "threadname.hh"

namespace dnsdist
{

LockGuarded<Carbon::Config> Carbon::s_config;

static bool doOneCarbonExport(const Carbon::Endpoint& endpoint)
{
  const auto& server = endpoint.server;
  const std::string& namespace_name = endpoint.namespace_name;
  const std::string& hostname = endpoint.ourname;
  const std::string& instance_name = endpoint.instance_name;

  try {
    Socket s(server.sin4.sin_family, SOCK_STREAM);
    s.setNonBlocking();
    s.connect(server); // we do the connect so the attempt happens while we gather stats
    ostringstream str;

    const time_t now = time(nullptr);

    {
      auto entries = g_stats.entries.read_lock();
      for (const auto& entry : *entries) {
        str << namespace_name << "." << hostname << "." << instance_name << "." << entry.d_name << ' ';
        if (const auto& val = boost::get<pdns::stat_t*>(&entry.d_value)) {
          str << (*val)->load();
        }
        else if (const auto& adval = boost::get<pdns::stat_t_trait<double>*>(&entry.d_value)) {
          str << (*adval)->load();
        }
        else if (const auto& dval = boost::get<double*>(&entry.d_value)) {
          str << **dval;
        }
        else if (const auto& func = boost::get<DNSDistStats::statfunction_t>(&entry.d_value)) {
          str << (*func)(entry.d_name);
        }
        str << ' ' << now << "\r\n";
      }
    }

    auto states = g_dstates.getLocal();
    for (const auto& state : *states) {
      string serverName = state->getName().empty() ? state->d_config.remote.toStringWithPort() : state->getName();
      boost::replace_all(serverName, ".", "_");
      const string base = namespace_name + "." + hostname + "." + instance_name + ".servers." + serverName + ".";
      str << base << "queries" << ' ' << state->queries.load() << " " << now << "\r\n";
      str << base << "responses" << ' ' << state->responses.load() << " " << now << "\r\n";
      str << base << "drops" << ' ' << state->reuseds.load() << " " << now << "\r\n";
      str << base << "latency" << ' ' << (state->d_config.availability != DownstreamState::Availability::Down ? state->latencyUsec / 1000.0 : 0) << " " << now << "\r\n";
      str << base << "latencytcp" << ' ' << (state->d_config.availability != DownstreamState::Availability::Down ? state->latencyUsecTCP / 1000.0 : 0) << " " << now << "\r\n";
      str << base << "senderrors" << ' ' << state->sendErrors.load() << " " << now << "\r\n";
      str << base << "outstanding" << ' ' << state->outstanding.load() << " " << now << "\r\n";
      str << base << "tcpdiedsendingquery" << ' ' << state->tcpDiedSendingQuery.load() << " " << now << "\r\n";
      str << base << "tcpdiedreaddingresponse" << ' ' << state->tcpDiedReadingResponse.load() << " " << now << "\r\n";
      str << base << "tcpgaveup" << ' ' << state->tcpGaveUp.load() << " " << now << "\r\n";
      str << base << "tcpreadimeouts" << ' ' << state->tcpReadTimeouts.load() << " " << now << "\r\n";
      str << base << "tcpwritetimeouts" << ' ' << state->tcpWriteTimeouts.load() << " " << now << "\r\n";
      str << base << "tcpconnecttimeouts" << ' ' << state->tcpConnectTimeouts.load() << " " << now << "\r\n";
      str << base << "tcpcurrentconnections" << ' ' << state->tcpCurrentConnections.load() << " " << now << "\r\n";
      str << base << "tcpmaxconcurrentconnections" << ' ' << state->tcpMaxConcurrentConnections.load() << " " << now << "\r\n";
      str << base << "tcpnewconnections" << ' ' << state->tcpNewConnections.load() << " " << now << "\r\n";
      str << base << "tcpreusedconnections" << ' ' << state->tcpReusedConnections.load() << " " << now << "\r\n";
      str << base << "tlsresumptions" << ' ' << state->tlsResumptions.load() << " " << now << "\r\n";
      str << base << "tcpavgqueriesperconnection" << ' ' << state->tcpAvgQueriesPerConnection.load() << " " << now << "\r\n";
      str << base << "tcpavgconnectionduration" << ' ' << state->tcpAvgConnectionDuration.load() << " " << now << "\r\n";
      str << base << "tcptoomanyconcurrentconnections" << ' ' << state->tcpTooManyConcurrentConnections.load() << " " << now << "\r\n";
      str << base << "healthcheckfailures" << ' ' << state->d_healthCheckMetrics.d_failures << " " << now << "\r\n";
      str << base << "healthcheckfailuresparsing" << ' ' << state->d_healthCheckMetrics.d_parseErrors << " " << now << "\r\n";
      str << base << "healthcheckfailurestimeout" << ' ' << state->d_healthCheckMetrics.d_timeOuts << " " << now << "\r\n";
      str << base << "healthcheckfailuresnetwork" << ' ' << state->d_healthCheckMetrics.d_networkErrors << " " << now << "\r\n";
      str << base << "healthcheckfailuresmismatch" << ' ' << state->d_healthCheckMetrics.d_mismatchErrors << " " << now << "\r\n";
      str << base << "healthcheckfailuresinvalid" << ' ' << state->d_healthCheckMetrics.d_invalidResponseErrors << " " << now << "\r\n";
    }

    std::map<std::string, uint64_t> frontendDuplicates;
    for (const auto& front : g_frontends) {
      if (front->udpFD == -1 && front->tcpFD == -1) {
        continue;
      }

      string frontName = front->local.toStringWithPort() + (front->udpFD >= 0 ? "_udp" : "_tcp");
      boost::replace_all(frontName, ".", "_");
      auto dupPair = frontendDuplicates.insert({frontName, 1});
      if (!dupPair.second) {
        frontName = frontName + "_" + std::to_string(dupPair.first->second);
        ++(dupPair.first->second);
      }

      const string base = namespace_name + "." + hostname + "." + instance_name + ".frontends." + frontName + ".";
      str << base << "queries" << ' ' << front->queries.load() << " " << now << "\r\n";
      str << base << "responses" << ' ' << front->responses.load() << " " << now << "\r\n";
      str << base << "tcpdiedreadingquery" << ' ' << front->tcpDiedReadingQuery.load() << " " << now << "\r\n";
      str << base << "tcpdiedsendingresponse" << ' ' << front->tcpDiedSendingResponse.load() << " " << now << "\r\n";
      str << base << "tcpgaveup" << ' ' << front->tcpGaveUp.load() << " " << now << "\r\n";
      str << base << "tcpclientimeouts" << ' ' << front->tcpClientTimeouts.load() << " " << now << "\r\n";
      str << base << "tcpdownstreamtimeouts" << ' ' << front->tcpDownstreamTimeouts.load() << " " << now << "\r\n";
      str << base << "tcpcurrentconnections" << ' ' << front->tcpCurrentConnections.load() << " " << now << "\r\n";
      str << base << "tcpmaxconcurrentconnections" << ' ' << front->tcpMaxConcurrentConnections.load() << " " << now << "\r\n";
      str << base << "tcpavgqueriesperconnection" << ' ' << front->tcpAvgQueriesPerConnection.load() << " " << now << "\r\n";
      str << base << "tcpavgconnectionduration" << ' ' << front->tcpAvgConnectionDuration.load() << " " << now << "\r\n";
      str << base << "tls10-queries" << ' ' << front->tls10queries.load() << " " << now << "\r\n";
      str << base << "tls11-queries" << ' ' << front->tls11queries.load() << " " << now << "\r\n";
      str << base << "tls12-queries" << ' ' << front->tls12queries.load() << " " << now << "\r\n";
      str << base << "tls13-queries" << ' ' << front->tls13queries.load() << " " << now << "\r\n";
      str << base << "tls-unknown-queries" << ' ' << front->tlsUnknownqueries.load() << " " << now << "\r\n";
      str << base << "tlsnewsessions" << ' ' << front->tlsNewSessions.load() << " " << now << "\r\n";
      str << base << "tlsresumptions" << ' ' << front->tlsResumptions.load() << " " << now << "\r\n";
      str << base << "tlsunknownticketkeys" << ' ' << front->tlsUnknownTicketKey.load() << " " << now << "\r\n";
      str << base << "tlsinactiveticketkeys" << ' ' << front->tlsInactiveTicketKey.load() << " " << now << "\r\n";

      const TLSErrorCounters* errorCounters = nullptr;
      if (front->tlsFrontend != nullptr) {
        errorCounters = &front->tlsFrontend->d_tlsCounters;
      }
      else if (front->dohFrontend != nullptr) {
        errorCounters = &front->dohFrontend->d_tlsCounters;
      }
      if (errorCounters != nullptr) {
        str << base << "tlsdhkeytoosmall" << ' ' << errorCounters->d_dhKeyTooSmall << " " << now << "\r\n";
        str << base << "tlsinappropriatefallback" << ' ' << errorCounters->d_inappropriateFallBack << " " << now << "\r\n";
        str << base << "tlsnosharedcipher" << ' ' << errorCounters->d_noSharedCipher << " " << now << "\r\n";
        str << base << "tlsunknownciphertype" << ' ' << errorCounters->d_unknownCipherType << " " << now << "\r\n";
        str << base << "tlsunknownkeyexchangetype" << ' ' << errorCounters->d_unknownKeyExchangeType << " " << now << "\r\n";
        str << base << "tlsunknownprotocol" << ' ' << errorCounters->d_unknownProtocol << " " << now << "\r\n";
        str << base << "tlsunsupportedec" << ' ' << errorCounters->d_unsupportedEC << " " << now << "\r\n";
        str << base << "tlsunsupportedprotocol" << ' ' << errorCounters->d_unsupportedProtocol << " " << now << "\r\n";
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
      str << base << "servers"
          << " " << pool->countServers(false) << " " << now << "\r\n";
      str << base << "servers-up"
          << " " << pool->countServers(true) << " " << now << "\r\n";
      if (pool->packetCache != nullptr) {
        const auto& cache = pool->packetCache;
        str << base << "cache-size"
            << " " << cache->getMaxEntries() << " " << now << "\r\n";
        str << base << "cache-entries"
            << " " << cache->getEntriesCount() << " " << now << "\r\n";
        str << base << "cache-hits"
            << " " << cache->getHits() << " " << now << "\r\n";
        str << base << "cache-misses"
            << " " << cache->getMisses() << " " << now << "\r\n";
        str << base << "cache-deferred-inserts"
            << " " << cache->getDeferredInserts() << " " << now << "\r\n";
        str << base << "cache-deferred-lookups"
            << " " << cache->getDeferredLookups() << " " << now << "\r\n";
        str << base << "cache-lookup-collisions"
            << " " << cache->getLookupCollisions() << " " << now << "\r\n";
        str << base << "cache-insert-collisions"
            << " " << cache->getInsertCollisions() << " " << now << "\r\n";
        str << base << "cache-ttl-too-shorts"
            << " " << cache->getTTLTooShorts() << " " << now << "\r\n";
        str << base << "cache-cleanup-count"
            << " " << cache->getCleanupCount() << " " << now << "\r\n";
      }
    }

#ifdef HAVE_DNS_OVER_HTTPS
    {
      std::map<std::string, uint64_t> dohFrontendDuplicates;
      const string base = "dnsdist." + hostname + ".main.doh.";
      for (const auto& doh : g_dohlocals) {
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

        vector<pair<const char*, const pdns::stat_t&>> v{
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
          {"valid-responses", doh->d_validresponses}};

        for (const auto& item : v) {
          str << base << name << "." << item.first << " " << item.second << " " << now << "\r\n";
        }
      }
    }
#endif /* HAVE_DNS_OVER_HTTPS */

    {
      std::string qname;
      auto records = g_qcount.records.write_lock();
      for (const auto& record : *records) {
        qname = record.first;
        boost::replace_all(qname, ".", "_");
        str << "dnsdist.querycount." << qname << ".queries " << record.second << " " << now << "\r\n";
      }
      records->clear();
    }

    const string msg = str.str();

    int ret = waitForRWData(s.getHandle(), false, 1, 0);
    if (ret <= 0) {
      vinfolog("Unable to write data to carbon server on %s: %s", server.toStringWithPort(), (ret < 0 ? stringerror() : "Timeout"));
      return false;
    }
    s.setBlocking();
    writen2(s.getHandle(), msg.c_str(), msg.size());
  }
  catch (const std::exception& e) {
    warnlog("Problem sending carbon data to %s: %s", server.toStringWithPort(), e.what());
    return false;
  }

  return true;
}

static void carbonHandler(Carbon::Endpoint&& endpoint)
{
  setThreadName("dnsdist/carbon");
  const auto intervalUSec = endpoint.interval * 1000 * 1000;
  /* maximum interval between two attempts is 10 minutes */
  const ExponentialBackOffTimer backOffTimer(10 * 60);

  try {
    uint8_t consecutiveFailures = 0;
    do {
      DTime dt;
      dt.set();
      if (doOneCarbonExport(endpoint)) {
        const auto elapsedUSec = dt.udiff();
        if (elapsedUSec < 0 || static_cast<unsigned int>(elapsedUSec) <= intervalUSec) {
          useconds_t toSleepUSec = intervalUSec - elapsedUSec;
          usleep(toSleepUSec);
        }
        else {
          vinfolog("Carbon export for %s took longer (%s usec) than the configured interval (%d usec)", endpoint.server.toStringWithPort(), elapsedUSec, intervalUSec);
        }
        consecutiveFailures = 0;
      }
      else {
        const auto backOff = backOffTimer.get(consecutiveFailures);
        if (consecutiveFailures < std::numeric_limits<decltype(consecutiveFailures)>::max()) {
          consecutiveFailures++;
        }
        vinfolog("Run for %s - %s failed, next attempt in %d", endpoint.server.toStringWithPort(), endpoint.ourname, backOff);
        sleep(backOff);
      }
    } while (true);
  }
  catch (const PDNSException& e) {
    errlog("Carbon thread for %s died, PDNSException: %s", endpoint.server.toStringWithPort(), e.reason);
  }
  catch (...) {
    errlog("Carbon thread for %s died", endpoint.server.toStringWithPort());
  }
}

bool Carbon::addEndpoint(Carbon::Endpoint&& endpoint)
{
  if (endpoint.ourname.empty()) {
    try {
      endpoint.ourname = getCarbonHostName();
    }
    catch (const std::exception& e) {
      throw std::runtime_error(std::string("The 'ourname' setting in 'carbonServer()' has not been set and we are unable to determine the system's hostname: ") + e.what());
    }
  }

  auto config = s_config.lock();
  if (config->d_running) {
    // we already started the threads, let's just spawn a new one
    std::thread newHandler(carbonHandler, std::move(endpoint));
    newHandler.detach();
  }
  else {
    config->d_endpoints.push_back(std::move(endpoint));
  }
  return true;
}

void Carbon::run()
{
  auto config = s_config.lock();
  if (config->d_running) {
    throw std::runtime_error("The carbon threads are already running");
  }
  for (auto& endpoint : config->d_endpoints) {
    std::thread newHandler(carbonHandler, std::move(endpoint));
    newHandler.detach();
  }
  config->d_endpoints.clear();
  config->d_running = true;
}

}
#endif /* DISABLE_CARBON */

static time_t s_start = time(nullptr);

uint64_t uptimeOfProcess(const std::string& str)
{
  return time(nullptr) - s_start;
}
