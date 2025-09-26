
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-snmp.hh"
#include "dolog.hh"

#include "ext/luawrapper/include/LuaContext.hpp"
RecursiveLockGuarded<LuaContext> g_lua{LuaContext()};

std::unique_ptr<DNSDistSNMPAgent> g_snmpAgent{nullptr};

#if BENCH_POLICIES
#include "dnsdist-rings.hh"
Rings g_rings;
#endif /* BENCH_POLICIES */

/* add stub implementations, we don't want to include the corresponding object files
   and their dependencies */

// NOLINTNEXTLINE(readability-convert-member-functions-to-static): this is a stub, the real one is not that simple..
bool TLSFrontend::setupTLS()
{
  return true;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static): this is a stub, the real one is not that simple..
bool DNSDistSNMPAgent::sendDNSTrap(const DNSQuestion& dnsQuestion, const std::string& reason)
{
  (void)dnsQuestion;
  (void)reason;
  return false;
}

void setLuaNoSideEffect()
{
}

bool setupDoTProtocolNegotiation(std::shared_ptr<TLSCtx>& tlsCtx)
{
  (void)tlsCtx;
  return true;
}

// NOLINTNEXTLINE(performance-unnecessary-value-param): this is a stub, the real one is not that simple and the performance does not matter
void responderThread(std::shared_ptr<DownstreamState> dss)
{
  (void)dss;
}

string g_outputBuffer;

static DNSQuestion getDQ(const DNSName* providedName = nullptr)
{
  static const DNSName qname("powerdns.com.");
  static PacketBuffer packet(sizeof(dnsheader));
  static InternalQueryState ids;
  ids.origDest = ComboAddress("127.0.0.1:53");
  ids.origRemote = ComboAddress("192.0.2.1:42");
  ids.qname = providedName != nullptr ? *providedName : qname;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.queryRealTime.start();

  DNSQuestion dnsQuestion(ids, packet);
  return dnsQuestion;
}

static void benchPolicy(const ServerPolicy& pol)
{
#if BENCH_POLICIES
  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.emplace_back("powerdns-" + std::to_string(idx) + ".com.");
  }
  ServerPolicy::NumberedServerVector servers;
  for (size_t idx = 1; idx <= 10; idx++) {
    servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
    servers.at(idx - 1).second->setUp();
    /* we need to have a weight of at least 1000 to get an optimal repartition with the consistent hashing algo */
    servers.at(idx - 1).second->setWeight(1000);
    /* make sure that the hashes have been computed */
    servers.at(idx - 1).second->hash();
  }

  StopWatch sw;
  sw.start();
  for (size_t idx = 0; idx < 1000; idx++) {
    for (const auto& name : names) {
      auto dnsQuestion = getDQ(&name);
      auto server = pol.getSelectedBackend(servers, dnsQuestion);
    }
  }
  cerr << pol.name << " took " << std::to_string(sw.udiff()) << " us for " << names.size() << endl;
#else
  (void)pol;
#endif /* BENCH_POLICIES */
}

static void resetLuaContext()
{
  /* we need to reset this before cleaning the Lua state because the server policy might holds
     a reference to a Lua function (Lua policies) */
  dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_lbPolicy = std::make_shared<ServerPolicy>("leastOutstanding", leastOutstanding, false);
  });
  /* we actually need this line to clear the cached state for this thread */
  BOOST_REQUIRE_EQUAL(dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy->getName(), "leastOutstanding");
  *(g_lua.lock()) = LuaContext();
}

BOOST_AUTO_TEST_SUITE(dnsdistlbpolicies)

#if 0
BOOST_AUTO_TEST_CASE(test_firstAvailable)
{
  auto dnsQuestion = getDQ();

  ServerPolicy pol{"firstAvailable", firstAvailable, false};
  ServerPolicy::NumberedServerVector servers;
  servers.emplace_back(1, std::make_shared<DownstreamState>(ComboAddress("192.0.2.1:53")));

  /* servers start as 'down' */
  auto server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_CHECK(server == nullptr);

  /* mark the server as 'up' */
  servers.at(0).second->setUp();
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_CHECK(server != nullptr);

  /* add a second server, we should still get the first one */
  servers.emplace_back(2, std::make_shared<DownstreamState>(ComboAddress("192.0.2.2:53")));
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(0).second);

  /* mark the first server as 'down', second as 'up' */
  servers.at(0).second->setDown();
  servers.at(1).second->setUp();
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(1).second);

  benchPolicy(pol);
}

BOOST_AUTO_TEST_CASE(test_firstAvailableWithOrderAndQPS)
{
  auto dnsQuestion = getDQ();
  size_t qpsLimit = 10;

  ServerPolicy pol{"firstAvailable", firstAvailable, false};
  ServerPolicy::NumberedServerVector servers;
  servers.emplace_back(1, std::make_shared<DownstreamState>(ComboAddress("192.0.2.1:53")));
  servers.emplace_back(2, std::make_shared<DownstreamState>(ComboAddress("192.0.2.2:53")));
  /* Second server has a higher order, so most queries should be routed to the first (remember that
     we need to keep them ordered!).
     However the first server has a QPS limit at 10 qps, so any query above that should be routed
     to the second server. */
  servers.at(0).second->d_config.order = 1;
  servers.at(1).second->d_config.order = 2;
  servers.at(0).second->qps = QPSLimiter(qpsLimit, qpsLimit);
  /* mark the servers as 'up' */
  servers.at(0).second->setUp();
  servers.at(1).second->setUp();

  /* the first queries under the QPS limit should be
     sent to the first server */
  for (size_t idx = 0; idx < qpsLimit; idx++) {
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(server != nullptr);
    BOOST_CHECK(server == servers.at(0).second);
    server->incQueriesCount();
  }

  /* then to the second server */
  for (size_t idx = 0; idx < 100; idx++) {
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(server != nullptr);
    BOOST_CHECK(server == servers.at(1).second);
    server->incQueriesCount();
  }
}

BOOST_AUTO_TEST_CASE(test_roundRobin)
{
  auto dnsQuestion = getDQ();

  ServerPolicy pol{"roundrobin", roundrobin, false};
  ServerPolicy::NumberedServerVector servers;

  /* selecting a server on an empty server list */
  dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_roundrobinFailOnNoServer = false;
  });
  auto server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_CHECK(server == nullptr);

  servers.emplace_back(1, std::make_shared<DownstreamState>(ComboAddress("192.0.2.1:53")));

  /* servers start as 'down' but the RR policy returns a server unless d_roundrobinFailOnNoServer is set */
  dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_roundrobinFailOnNoServer = true;
  });
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_CHECK(server == nullptr);
  dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_roundrobinFailOnNoServer = false;
  });
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_CHECK(server != nullptr);

  /* mark the server as 'up' */
  servers.at(0).second->setUp();
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_CHECK(server != nullptr);

  /* add a second server, we should get the first one then the second one */
  servers.emplace_back(2, std::make_shared<DownstreamState>(ComboAddress("192.0.2.2:53")));
  servers.at(1).second->setUp();
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(0).second);
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(1).second);

  /* mark the first server as 'down', second as 'up' */
  servers.at(0).second->setDown();
  servers.at(1).second->setUp();
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(1).second);

  std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
  /* mark all servers 'up' */
  for (auto& serv : servers) {
    serv.second->setUp();
    serversMap[serv.second] = 0;
  }

  for (size_t idx = 0; idx < 1000; idx++) {
    server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }
  uint64_t total = 0;
  for (const auto& entry : serversMap) {
    BOOST_CHECK_EQUAL(entry.second, 1000 / servers.size());
    total += entry.second;
  }
  BOOST_CHECK_EQUAL(total, 1000U);

  benchPolicy(pol);
}

BOOST_AUTO_TEST_CASE(test_leastOutstanding)
{
  auto dnsQuestion = getDQ();

  ServerPolicy pol{"leastOutstanding", leastOutstanding, false};
  ServerPolicy::NumberedServerVector servers;
  servers.emplace_back(1, std::make_shared<DownstreamState>(ComboAddress("192.0.2.1:53")));

  /* servers start as 'down' */
  auto server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_CHECK(server == nullptr);

  /* mark the server as 'up' */
  servers.at(0).second->setUp();
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_CHECK(server != nullptr);

  /* add a second server, we should still get the first one */
  servers.emplace_back(2, std::make_shared<DownstreamState>(ComboAddress("192.0.2.2:53")));
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(0).second);

  /* mark the first server as 'down', second as 'up' */
  servers.at(0).second->setDown();
  servers.at(1).second->setUp();
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(1).second);

  /* mark both servers as 'up', increase the outstanding count of the first one */
  servers.at(0).second->setUp();
  servers.at(0).second->outstanding = 42;
  servers.at(1).second->setUp();
  server = pol.getSelectedBackend(servers, dnsQuestion);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(1).second);

  benchPolicy(pol);
}

BOOST_AUTO_TEST_CASE(test_wrandom)
{
  auto dnsQuestion = getDQ();

  ServerPolicy pol{"wrandom", wrandom, false};
  ServerPolicy::NumberedServerVector servers;
  std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
  for (size_t idx = 1; idx <= 10; idx++) {
    servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
    serversMap[servers.at(idx - 1).second] = 0;
    servers.at(idx - 1).second->setUp();
  }

  benchPolicy(pol);

  for (size_t idx = 0; idx < 1000; idx++) {
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }
  uint64_t total = 0;
  for (const auto& entry : serversMap) {
    BOOST_CHECK_GT(entry.second, 0U);
    BOOST_CHECK_GT(entry.second, (1000 / servers.size() / 2));
    BOOST_CHECK_LT(entry.second, (1000 / servers.size() * 2));
    total += entry.second;
  }
  BOOST_CHECK_EQUAL(total, 1000U);

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->d_config.d_weight, 1);
  }

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->d_config.d_weight, 1);
  }
  /* change the weight of the last server to 100, default is 1 */
  servers.at(servers.size() - 1).second->d_config.d_weight = 100;

  for (size_t idx = 0; idx < 1000; idx++) {
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }

  total = 0;
  uint64_t totalW = 0;
  for (const auto& entry : serversMap) {
    total += entry.second;
    totalW += entry.first->d_config.d_weight;
  }
  BOOST_CHECK_EQUAL(total, 1000U);
  auto last = servers.at(servers.size() - 1).second;
  const auto got = serversMap[last];
  float expected = static_cast<float>(1000 * 1.0 * last->d_config.d_weight) / static_cast<float>(totalW);
  BOOST_CHECK_GT(got, expected / 2);
  BOOST_CHECK_LT(got, expected * 2);
}

BOOST_AUTO_TEST_CASE(test_whashed)
{
  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.emplace_back("powerdns-" + std::to_string(idx) + ".com.");
  }

  ServerPolicy pol{"whashed", whashed, false};
  ServerPolicy::NumberedServerVector servers;
  std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
  for (size_t idx = 1; idx <= 10; idx++) {
    servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
    serversMap[servers.at(idx - 1).second] = 0;
    servers.at(idx - 1).second->setUp();
  }

  benchPolicy(pol);

  for (const auto& name : names) {
    auto dnsQuestion = getDQ(&name);
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }

  uint64_t total = 0;
  for (const auto& entry : serversMap) {
    BOOST_CHECK_GT(entry.second, 0U);
    BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
    BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
    total += entry.second;
  }
  BOOST_CHECK_EQUAL(total, names.size());

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->d_config.d_weight, 1);
  }

  /* request 1000 times the same name, we should go to the same server every time */
  {
    auto dnsQuestion = getDQ(&names.at(0));
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    for (size_t idx = 0; idx < 1000; idx++) {
      BOOST_CHECK(pol.getSelectedBackend(servers, dnsQuestion) == server);
    }
  }

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->d_config.d_weight, 1);
  }
  /* change the weight of the last server to 100, default is 1 */
  servers.at(servers.size() - 1).second->setWeight(100);

  for (const auto& name : names) {
    auto dnsQuestion = getDQ(&name);
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }

  total = 0;
  uint64_t totalW = 0;
  for (const auto& entry : serversMap) {
    total += entry.second;
    totalW += entry.first->d_config.d_weight;
  }
  BOOST_CHECK_EQUAL(total, names.size());
  auto last = servers.at(servers.size() - 1).second;
  const auto got = serversMap[last];
  float expected = static_cast<float>(static_cast<double>(names.size()) * 1.0 * last->d_config.d_weight) / static_cast<float>(totalW);
  BOOST_CHECK_GT(got, expected / 2);
  BOOST_CHECK_LT(got, expected * 2);
}

BOOST_AUTO_TEST_CASE(test_chashed)
{
  bool existingVerboseValue = dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose;
  dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_verbose = false;
  });

  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.emplace_back("powerdns-" + std::to_string(idx) + ".com.");
  }

  ServerPolicy pol{"chashed", chashed, false};
  ServerPolicy::NumberedServerVector servers;
  std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
  for (size_t idx = 1; idx <= 10; idx++) {
    servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
    serversMap[servers.at(idx - 1).second] = 0;
    servers.at(idx - 1).second->setUp();
    /* we need to have a weight of at least 1000 to get an optimal repartition with the consistent hashing algo */
    servers.at(idx - 1).second->setWeight(1000);
    /* make sure that the hashes have been computed */
    servers.at(idx - 1).second->hash();
  }

  benchPolicy(pol);

  for (const auto& name : names) {
    auto dnsQuestion = getDQ(&name);
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }

  uint64_t total = 0;
  for (const auto& entry : serversMap) {
    BOOST_CHECK_GT(entry.second, 0U);
    BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
    BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
    total += entry.second;
  }
  BOOST_CHECK_EQUAL(total, names.size());

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->d_config.d_weight, 1000);
  }

  /* request 1000 times the same name, we should go to the same server every time */
  {
    auto dnsQuestion = getDQ(&names.at(0));
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    for (size_t idx = 0; idx < 1000; idx++) {
      BOOST_CHECK(pol.getSelectedBackend(servers, dnsQuestion) == server);
    }
  }

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->d_config.d_weight, 1000);
  }
  /* change the weight of the last server to 100000, others stay at 1000 */
  servers.at(servers.size() - 1).second->setWeight(100000);

  for (const auto& name : names) {
    auto dnsQuestion = getDQ(&name);
    auto server = pol.getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }

  total = 0;
  uint64_t totalW = 0;
  for (const auto& entry : serversMap) {
    total += entry.second;
    totalW += entry.first->d_config.d_weight;
  }
  BOOST_CHECK_EQUAL(total, names.size());
  auto last = servers.at(servers.size() - 1).second;
  const auto got = serversMap[last];
  float expected = static_cast<float>(static_cast<double>(names.size()) * 1.0 * last->d_config.d_weight) / static_cast<float>(totalW);
  BOOST_CHECK_GT(got, expected / 2);
  BOOST_CHECK_LT(got, expected * 2);

  dnsdist::configuration::updateRuntimeConfiguration([existingVerboseValue](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_verbose = existingVerboseValue;
  });
}
#endif

BOOST_AUTO_TEST_CASE(test_lua)
{
  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.emplace_back("powerdns-" + std::to_string(idx) + ".com.");
  }

  static const std::string policySetupStr = R"foo(
    local counter = 0
    function luaroundrobin(servers, dq)
      counter = counter + 1
      return 1 + (counter % #servers)
    end

    setServerPolicyLua("luaroundrobin", luaroundrobin)
  )foo";
  resetLuaContext();
  g_lua.lock()->writeFunction("setServerPolicyLua", [](const string& name, const ServerPolicy::policyfunc_t& policy) {
    auto pol = std::make_shared<ServerPolicy>(name, policy, true);
    dnsdist::configuration::updateRuntimeConfiguration([&pol](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_lbPolicy = std::move(pol);
    });
  });
  g_lua.lock()->executeCode(policySetupStr);

  {
    const auto& pol = dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy;
    BOOST_REQUIRE(pol != nullptr);
    BOOST_REQUIRE(pol != nullptr);
    ServerPolicy::NumberedServerVector servers;
    std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
    for (size_t idx = 1; idx <= 10; idx++) {
      servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
      serversMap[servers.at(idx - 1).second] = 0;
      servers.at(idx - 1).second->setUp();
    }
    BOOST_REQUIRE_EQUAL(servers.size(), 10U);

    for (const auto& name : names) {
      auto dnsQuestion = getDQ(&name);
      auto selectedServer = pol->getSelectedBackend(servers, dnsQuestion);
      BOOST_REQUIRE(selectedServer);
      const auto& server = selectedServer.get();
      BOOST_REQUIRE(serversMap.count(server) == 1);
      ++serversMap[server];
    }

    uint64_t total = 0;
    for (const auto& entry : serversMap) {
      BOOST_CHECK_GT(entry.second, 0U);
      BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
      BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
      total += entry.second;
    }
    BOOST_CHECK_EQUAL(total, names.size());

    benchPolicy(*pol);
  }
  resetLuaContext();
}
#if 0
#ifdef LUAJIT_VERSION

BOOST_AUTO_TEST_CASE(test_lua_ffi_rr)
{
  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.emplace_back("powerdns-" + std::to_string(idx) + ".com.");
  }

  static const std::string policySetupStr = R"foo(
    local ffi = require("ffi")
    local C = ffi.C
    local counter = 0
    function ffilb(servers_list, dq)
      local serversCount = tonumber(C.dnsdist_ffi_servers_list_get_count(servers_list))
      counter = counter + 1
      return counter % serversCount
    end

    setServerPolicyLuaFFI("FFI round-robin", ffilb)
  )foo";
  resetLuaContext();
  g_lua.lock()->executeCode(getLuaFFIWrappers());
  g_lua.lock()->writeFunction("setServerPolicyLuaFFI", [](const string& name, const ServerPolicy::ffipolicyfunc_t& policy) {
    auto pol = std::make_shared<ServerPolicy>(name, std::move(policy));
    dnsdist::configuration::updateRuntimeConfiguration([&pol](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_lbPolicy = std::move(pol);
    });
  });
  g_lua.lock()->executeCode(policySetupStr);

  {
    const auto& pol = dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy;
    BOOST_REQUIRE(pol != nullptr);
    ServerPolicy::NumberedServerVector servers;
    std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
    for (size_t idx = 1; idx <= 10; idx++) {
      servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
      serversMap[servers.at(idx - 1).second] = 0;
      servers.at(idx - 1).second->setUp();
    }
    BOOST_REQUIRE_EQUAL(servers.size(), 10U);

    for (const auto& name : names) {
      auto dnsQuestion = getDQ(&name);
      auto server = pol->getSelectedBackend(servers, dnsQuestion);
      BOOST_REQUIRE(serversMap.count(server) == 1);
      ++serversMap[server];
    }

    uint64_t total = 0;
    for (const auto& entry : serversMap) {
      BOOST_CHECK_GT(entry.second, 0U);
      BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
      BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
      total += entry.second;
    }
    BOOST_CHECK_EQUAL(total, names.size());

    benchPolicy(*pol);
  }
  resetLuaContext();
}

BOOST_AUTO_TEST_CASE(test_lua_ffi_no_server_available)
{
  DNSName dnsName("powerdns.com.");
  static const std::string policySetupStr = R"foo(
    local ffi = require("ffi")
    local C = ffi.C
    local counter = 0
    function ffipolicy(servers_list, dq)
      local serversCount = tonumber(C.dnsdist_ffi_servers_list_get_count(servers_list))
      -- return clearly out of bounds value to indicate that no server can be used
      return serversCount + 100
    end

    setServerPolicyLuaFFI("FFI policy", ffipolicy)
  )foo";
  resetLuaContext();
  g_lua.lock()->executeCode(getLuaFFIWrappers());
  g_lua.lock()->writeFunction("setServerPolicyLuaFFI", [](const string& policyName, ServerPolicy::ffipolicyfunc_t policy) {
    auto pol = std::make_shared<ServerPolicy>(policyName, std::move(policy));
    dnsdist::configuration::updateRuntimeConfiguration([&pol](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_lbPolicy = std::move(pol);
    });
  });
  g_lua.lock()->executeCode(policySetupStr);

  {
    const auto& pol = dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy;
    BOOST_REQUIRE(pol != nullptr);
    ServerPolicy::NumberedServerVector servers;
    for (size_t idx = 1; idx <= 10; idx++) {
      servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
      servers.at(idx - 1).second->setUp();
    }
    BOOST_REQUIRE_EQUAL(servers.size(), 10U);

    auto dnsQuestion = getDQ(&dnsName);
    auto server = pol->getSelectedBackend(servers, dnsQuestion);
    BOOST_REQUIRE(server == nullptr);
  }
  resetLuaContext();
}

BOOST_AUTO_TEST_CASE(test_lua_ffi_hashed)
{
  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.emplace_back("powerdns-" + std::to_string(idx) + ".com.");
  }

  static const std::string policySetupStr = R"foo(
    local ffi = require("ffi")
    local C = ffi.C
    function ffilb(servers_list, dq)
      local serversCount = tonumber(C.dnsdist_ffi_servers_list_get_count(servers_list))
      local hash = tonumber(C.dnsdist_ffi_dnsquestion_get_qname_hash(dq, 0))
      return hash % serversCount
    end

    setServerPolicyLuaFFI("FFI hashed", ffilb)
  )foo";
  resetLuaContext();
  g_lua.lock()->executeCode(getLuaFFIWrappers());
  g_lua.lock()->writeFunction("setServerPolicyLuaFFI", [](const string& name, const ServerPolicy::ffipolicyfunc_t& policy) {
    auto pol = std::make_shared<ServerPolicy>(name, std::move(policy));
    dnsdist::configuration::updateRuntimeConfiguration([&pol](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_lbPolicy = std::move(pol);
    });
  });
  g_lua.lock()->executeCode(policySetupStr);

  {
    const auto& pol = dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy;
    BOOST_REQUIRE(pol != nullptr);
    ServerPolicy::NumberedServerVector servers;
    std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
    for (size_t idx = 1; idx <= 10; idx++) {
      servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
      serversMap[servers.at(idx - 1).second] = 0;
      servers.at(idx - 1).second->setUp();
    }
    BOOST_REQUIRE_EQUAL(servers.size(), 10U);

    for (const auto& name : names) {
      auto dnsQuestion = getDQ(&name);
      auto server = pol->getSelectedBackend(servers, dnsQuestion);
      BOOST_REQUIRE(serversMap.count(server) == 1);
      ++serversMap[server];
    }

    uint64_t total = 0;
    for (const auto& entry : serversMap) {
      BOOST_CHECK_GT(entry.second, 0U);
      BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
      BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
      total += entry.second;
    }
    BOOST_CHECK_EQUAL(total, names.size());

    benchPolicy(*pol);
  }
  resetLuaContext();
}

BOOST_AUTO_TEST_CASE(test_lua_ffi_whashed)
{
  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.emplace_back("powerdns-" + std::to_string(idx) + ".com.");
  }

  static const std::string policySetupStr = R"foo(
    local ffi = require("ffi")
    local C = ffi.C
    function ffilb(servers_list, dq)
      return tonumber(C.dnsdist_ffi_servers_list_whashed(servers_list, dq, C.dnsdist_ffi_dnsquestion_get_qname_hash(dq, 0)))
    end

    setServerPolicyLuaFFI("FFI whashed", ffilb)
  )foo";
  resetLuaContext();
  g_lua.lock()->executeCode(getLuaFFIWrappers());
  g_lua.lock()->writeFunction("setServerPolicyLuaFFI", [](const string& name, const ServerPolicy::ffipolicyfunc_t& policy) {
    auto pol = std::make_shared<ServerPolicy>(name, std::move(policy));
    dnsdist::configuration::updateRuntimeConfiguration([&pol](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_lbPolicy = std::move(pol);
    });
  });
  g_lua.lock()->executeCode(policySetupStr);

  {
    const auto& pol = dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy;
    BOOST_REQUIRE(pol != nullptr);
    ServerPolicy::NumberedServerVector servers;
    std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
    for (size_t idx = 1; idx <= 10; idx++) {
      servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
      serversMap[servers.at(idx - 1).second] = 0;
      servers.at(idx - 1).second->setUp();
    }
    BOOST_REQUIRE_EQUAL(servers.size(), 10U);

    for (const auto& name : names) {
      auto dnsQuestion = getDQ(&name);
      auto server = pol->getSelectedBackend(servers, dnsQuestion);
      BOOST_REQUIRE(serversMap.count(server) == 1);
      ++serversMap[server];
    }

    uint64_t total = 0;
    for (const auto& entry : serversMap) {
      BOOST_CHECK_GT(entry.second, 0U);
      BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
      BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
      total += entry.second;
    }
    BOOST_CHECK_EQUAL(total, names.size());

    benchPolicy(*pol);
  }
  resetLuaContext();
}

BOOST_AUTO_TEST_CASE(test_lua_ffi_chashed)
{
  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.emplace_back("powerdns-" + std::to_string(idx) + ".com.");
  }

  static const std::string policySetupStr = R"foo(
    local ffi = require("ffi")
    local C = ffi.C
    function ffilb(servers_list, dq)
      return tonumber(C.dnsdist_ffi_servers_list_chashed(servers_list, dq, C.dnsdist_ffi_dnsquestion_get_qname_hash(dq, 0)))
    end

    setServerPolicyLuaFFI("FFI chashed", ffilb)
  )foo";
  resetLuaContext();
  g_lua.lock()->executeCode(getLuaFFIWrappers());
  g_lua.lock()->writeFunction("setServerPolicyLuaFFI", [](const string& name, const ServerPolicy::ffipolicyfunc_t& policy) {
    auto pol = std::make_shared<ServerPolicy>(name, std::move(policy));
    dnsdist::configuration::updateRuntimeConfiguration([&pol](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_lbPolicy = std::move(pol);
    });
  });
  g_lua.lock()->executeCode(policySetupStr);

  {
    const auto& pol = dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy;
    BOOST_REQUIRE(pol != nullptr);
    ServerPolicy::NumberedServerVector servers;
    std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
    for (size_t idx = 1; idx <= 10; idx++) {
      servers.emplace_back(idx, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")));
      serversMap[servers.at(idx - 1).second] = 0;
      servers.at(idx - 1).second->setUp();
      /* we need to have a weight of at least 1000 to get an optimal repartition with the consistent hashing algo */
      servers.at(idx - 1).second->setWeight(1000);
      /* make sure that the hashes have been computed */
      servers.at(idx - 1).second->hash();
    }
    BOOST_REQUIRE_EQUAL(servers.size(), 10U);

    for (const auto& name : names) {
      auto dnsQuestion = getDQ(&name);
      auto server = pol->getSelectedBackend(servers, dnsQuestion);
      BOOST_REQUIRE(serversMap.count(server) == 1);
      ++serversMap[server];
    }

    uint64_t total = 0;
    for (const auto& entry : serversMap) {
      BOOST_CHECK_GT(entry.second, 0U);
      BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
      BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
      total += entry.second;
    }
    BOOST_CHECK_EQUAL(total, names.size());

    benchPolicy(*pol);
  }
  resetLuaContext();
}

#endif /* LUAJIT_VERSION */
#endif
BOOST_AUTO_TEST_SUITE_END()
