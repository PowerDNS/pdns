#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include <cstdio>

#include "test-syncres_cc.hh"
#include "reczones-helpers.hh"

BOOST_AUTO_TEST_SUITE(reczones_helpers)

static const std::array<std::string, 10> hostLines = {
  "192.168.0.1             foo bar\n",
  "192.168.0.1             dupfoo\n",
  "192.168.0.2             baz\n",
  "1.1.1.1                 fancy\n",
  "2.2.2.2                 more.fancy\n",
  "2001:db8::567:89ab      foo6 bar6\n",
  "2001:db8::567:89ab      dupfoo6\n",
  "127.0.0.1               localhost\n",
  "::1                     localhost self\n",
  "2001:db8::567:89ac      some.address.somewhere some some.address\n",
};

struct Fixture
{
  static std::shared_ptr<DNSRecordContent> makeLocalhostRootDRC()
  {
    return DNSRecordContent::make(QType::SOA, QClass::IN, "localhost. root 1 604800 86400 2419200 604800");
  }

  static std::shared_ptr<DNSRecordContent> makeLocalhostDRC()
  {
    return DNSRecordContent::make(QType::NS, QClass::IN, "localhost.");
  }

  static std::shared_ptr<DNSRecordContent> makePtrDRC(const std::string& name)
  {
    return DNSRecordContent::make(QType::PTR, QClass::IN, name);
  }

  static void addDomainMapFixtureEntry(SyncRes::domainmap_t& domainMap,
                                       const std::string& name,
                                       const SyncRes::AuthDomain::records_t& records)
  {
    domainMap[DNSName{name}] = SyncRes::AuthDomain{
      .d_records = records,
      .d_servers = {},
      .d_name = DNSName{name},
      .d_rdForward = false,
    };
  }

  static void addDomainMapFixtureEntry(SyncRes::domainmap_t& domainMap,
                                       const std::string& name,
                                       const QType type,
                                       const std::string& address)
  {
    domainMap[DNSName{name}] = SyncRes::AuthDomain{
      .d_records = {
        DNSRecord(name, DNSRecordContent::make(type, QClass::IN, address), type),
        DNSRecord(name, makeLocalhostDRC(), QType::NS),
        DNSRecord(name, makeLocalhostRootDRC(), QType::SOA),
      },
      .d_servers = {},
      .d_name = DNSName{name},
      .d_rdForward = false,
    };
  }

  static void populateDomainMapFixture(SyncRes::domainmap_t& domainMap,
                                       const std::string& searchSuffix = "")
  {
    const auto actualSearchSuffix = searchSuffix.empty() ? "" : "." + searchSuffix;

    addDomainMapFixtureEntry(domainMap, "foo" + actualSearchSuffix, QType::A, "192.168.0.1");
    addDomainMapFixtureEntry(domainMap, "bar" + actualSearchSuffix, QType::A, "192.168.0.1");
    addDomainMapFixtureEntry(domainMap, "dupfoo" + actualSearchSuffix, QType::A, "192.168.0.1");
    addDomainMapFixtureEntry(
      domainMap,
      "1.0.168.192.in-addr.arpa",
      {
        DNSRecord("1.0.168.192.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("1.0.168.192.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("1.0.168.192.in-addr.arpa", makePtrDRC("foo" + actualSearchSuffix), QType::PTR),
      });
    addDomainMapFixtureEntry(domainMap, "baz" + actualSearchSuffix, QType::A, "192.168.0.2");
    addDomainMapFixtureEntry(
      domainMap,
      "2.0.168.192.in-addr.arpa",
      {
        DNSRecord("2.0.168.192.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("2.0.168.192.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("2.0.168.192.in-addr.arpa", makePtrDRC("baz" + actualSearchSuffix), QType::PTR),
      });
    addDomainMapFixtureEntry(domainMap, "fancy" + actualSearchSuffix, QType::A, "1.1.1.1");
    addDomainMapFixtureEntry(
      domainMap,
      "1.1.1.1.in-addr.arpa",
      {
        DNSRecord("1.1.1.1.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("1.1.1.1.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("1.1.1.1.in-addr.arpa", makePtrDRC("fancy" + actualSearchSuffix), QType::PTR),
      });
    addDomainMapFixtureEntry(domainMap, "more.fancy", QType::A, "2.2.2.2");
    addDomainMapFixtureEntry(
      domainMap,
      "2.2.2.2.in-addr.arpa",
      {
        DNSRecord("2.2.2.2.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("2.2.2.2.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("2.2.2.2.in-addr.arpa", makePtrDRC("more.fancy."), QType::PTR),
      });

    addDomainMapFixtureEntry(domainMap, "foo6" + actualSearchSuffix, QType::AAAA, "2001:db8::567:89ab");
    addDomainMapFixtureEntry(domainMap, "bar6" + actualSearchSuffix, QType::AAAA, "2001:db8::567:89ab");
    addDomainMapFixtureEntry(domainMap, "dupfoo6" + actualSearchSuffix, QType::AAAA, "2001:db8::567:89ab");
    addDomainMapFixtureEntry(
      domainMap,
      "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
      {
        DNSRecord("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makePtrDRC("foo6" + actualSearchSuffix), QType::PTR),
      });

    addDomainMapFixtureEntry(
      domainMap,
      "localhost" + actualSearchSuffix,
      {DNSRecord("localhost" + actualSearchSuffix, makeLocalhostDRC(), QType::NS),
       DNSRecord("localhost" + actualSearchSuffix, makeLocalhostRootDRC(), QType::SOA),
       DNSRecord("localhost" + actualSearchSuffix, DNSRecordContent::make(QType::AAAA, QClass::IN, "::1"), QType::AAAA),
       DNSRecord("localhost" + actualSearchSuffix, DNSRecordContent::make(QType::A, QClass::IN, "127.0.0.1"), QType::A)});
    addDomainMapFixtureEntry(domainMap, "self" + actualSearchSuffix, QType::AAAA, "::1");
    addDomainMapFixtureEntry(
      domainMap,
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
      {
        DNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", makePtrDRC("localhost" + actualSearchSuffix), QType::PTR),
      });
    addDomainMapFixtureEntry(
      domainMap,
      "1.0.0.127.in-addr.arpa",
      {
        DNSRecord("1.0.0.127.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("1.0.0.127.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("1.0.0.127.in-addr.arpa", makePtrDRC("localhost" + actualSearchSuffix), QType::PTR),
      });

    addDomainMapFixtureEntry(domainMap, "some" + actualSearchSuffix, QType::AAAA, "2001:db8::567:89ac");
    addDomainMapFixtureEntry(domainMap, "some.address.somewhere", QType::AAAA, "2001:db8::567:89ac");
    addDomainMapFixtureEntry(domainMap, "some.address", QType::AAAA, "2001:db8::567:89ac");
    addDomainMapFixtureEntry(
      domainMap,
      "c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
      {
        DNSRecord("c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makePtrDRC("some.address.somewhere."), QType::PTR),
      });
  }

  Fixture()
  {
    populateDomainMapFixture(domainMapFixture);
    populateDomainMapFixture(domainMapFixtureWithSearchSuffix, "search.suffix");
  }

  using DomainMapEntry = std::pair<DNSName, SyncRes::AuthDomain>;

  static std::vector<DomainMapEntry> sortDomainMap(const SyncRes::domainmap_t& domainMap)
  {
    std::vector<DomainMapEntry> sorted{};
    sorted.reserve(domainMap.size());
    for (const auto& pair : domainMap) {
      sorted.emplace_back(pair.first, pair.second);
    }
    std::stable_sort(std::begin(sorted), std::end(sorted), [](const DomainMapEntry& a, const DomainMapEntry& b) {
      return a.first < b.first && a.second.d_name < b.second.d_name;
    });
    return sorted;
  }

  static std::string printDomainMap(const std::vector<DomainMapEntry>& domainMap)
  {
    std::stringstream s{};
    for (const auto& entry : domainMap) {
      s << "Entry `" << entry.first << "` {" << std::endl;
      s << entry.second.print("  ");
      s << "}" << std::endl;
    }
    return s.str();
  }

  std::vector<DomainMapEntry> getDomainMapFixture() const
  {
    return sortDomainMap(domainMapFixture);
  }

  std::vector<DomainMapEntry> getDomainMapFixtureWithSearchSuffix() const
  {
    return sortDomainMap(domainMapFixtureWithSearchSuffix);
  }

private:
  SyncRes::domainmap_t domainMapFixture{};
  SyncRes::domainmap_t domainMapFixtureWithSearchSuffix{};
};

BOOST_FIXTURE_TEST_CASE(test_loading_etc_hosts, Fixture)
{
  auto log = g_slog->withName("config");

  auto domainMap = std::make_shared<SyncRes::domainmap_t>();
  auto domainMapWithSearchSuffix = std::make_shared<SyncRes::domainmap_t>();
  std::vector<std::string> parts{};
  for (auto line : hostLines) {
    BOOST_REQUIRE(parseEtcHostsLine(parts, line));
    addForwardAndReverseLookupEntries(*domainMap, "", parts, log);
    addForwardAndReverseLookupEntries(*domainMapWithSearchSuffix, "search.suffix", parts, log);
  }

  BOOST_TEST_MESSAGE("Actual and expected outputs without search suffixes:");

  auto actual = sortDomainMap(*domainMap);
  BOOST_TEST_MESSAGE("Actual:");
  BOOST_TEST_MESSAGE(printDomainMap(actual));

  auto expected = getDomainMapFixture();
  BOOST_TEST_MESSAGE("Expected:");
  BOOST_TEST_MESSAGE(printDomainMap(expected));

  BOOST_CHECK_EQUAL(actual.size(), expected.size());
  for (std::vector<DomainMapEntry>::size_type i = 0; i < actual.size(); i++) {
    BOOST_CHECK(actual[i].first == expected[i].first);
    BOOST_CHECK(actual[i].second == expected[i].second);
  }

  BOOST_TEST_MESSAGE("-----------------------------------------------------");

  BOOST_TEST_MESSAGE("Actual and expected outputs with search suffixes:");

  auto actualSearchSuffix = sortDomainMap(*domainMapWithSearchSuffix);
  BOOST_TEST_MESSAGE("Actual (with search suffix):");
  BOOST_TEST_MESSAGE(printDomainMap(actualSearchSuffix));

  auto expectedSearchSuffix = getDomainMapFixtureWithSearchSuffix();
  BOOST_TEST_MESSAGE("Expected (with search suffix):");
  BOOST_TEST_MESSAGE(printDomainMap(expectedSearchSuffix));

  BOOST_CHECK_EQUAL(actualSearchSuffix.size(), expectedSearchSuffix.size());
  for (std::vector<DomainMapEntry>::size_type i = 0; i < actualSearchSuffix.size(); i++) {
    BOOST_CHECK(actualSearchSuffix[i].first == expectedSearchSuffix[i].first);
    BOOST_CHECK(actualSearchSuffix[i].second == expectedSearchSuffix[i].second);
  }

  BOOST_TEST_MESSAGE("-----------------------------------------------------");
}

const std::string hints = ". 3600 IN NS ns.\n"
                          ". 3600 IN NS ns1.\n"
                          "ns. 3600 IN A 192.168.178.16\n"
                          "ns. 3600 IN A 192.168.178.17\n"
                          "ns. 3600 IN A 192.168.178.18\n"
                          "ns. 3600 IN AAAA 1::2\n"
                          "ns. 3600 IN AAAA 1::3\n"
                          "ns1. 3600 IN A 192.168.178.18\n";

BOOST_AUTO_TEST_CASE(test_UserHints)
{
  MemRecursorCache::resetStaticsForTests();
  g_recCache = make_unique<MemRecursorCache>();

  ::arg().set("max-generate-steps") = "0";
  ::arg().set("max-include-depth") = "0";
  string temp{"/tmp/hintsXXXXXXXXXX"};
  int fileDesc = mkstemp(temp.data());
  BOOST_REQUIRE(fileDesc > 0);
  FILE* filePointer = fdopen(fileDesc, "w");
  BOOST_REQUIRE(filePointer != nullptr);
  size_t written = fwrite(hints.data(), 1, hints.length(), filePointer);
  BOOST_REQUIRE(written == hints.length());
  BOOST_REQUIRE(fclose(filePointer) == 0); // NOLINT

  time_t now = time(nullptr);
  std::vector<DNSRecord> nsvec;

  auto readOK = readHintsIntoCache(now, std::string(temp), nsvec);
  unlink(temp.data());
  BOOST_CHECK(readOK);
  BOOST_CHECK_EQUAL(nsvec.size(), 2U);

  const MemRecursorCache::Flags flags = 0;

  BOOST_CHECK(g_recCache->get(now, DNSName("ns"), QType::A, flags, &nsvec, ComboAddress()) > 0);
  BOOST_CHECK_EQUAL(nsvec.size(), 3U);

  BOOST_CHECK(g_recCache->get(now, DNSName("ns"), QType::AAAA, flags, &nsvec, ComboAddress()) > 0);
  BOOST_CHECK_EQUAL(nsvec.size(), 2U);

  BOOST_CHECK(g_recCache->get(now, DNSName("ns1"), QType::A, flags, &nsvec, ComboAddress()) > 0);
  BOOST_CHECK_EQUAL(nsvec.size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
