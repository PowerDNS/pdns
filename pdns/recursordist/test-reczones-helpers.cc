#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include <stdio.h>

#include "test-syncres_cc.hh"
#include "reczones-helpers.hh"

BOOST_AUTO_TEST_SUITE(reczones_helpers)

static const std::array<std::string, 9> hostLines = {
  "192.168.0.1             foo bar\n",
  "192.168.0.1             dupfoo\n",
  "192.168.0.2             baz\n",
  "1.1.1.1                 fancy\n",
  "2.2.2.2                 more.fancy\n",
  "2001:db8::567:89ab      foo6 bar6\n",
  "2001:db8::567:89ab      dupfoo6\n",
  "::1                     localhost self\n",
  "2001:db8::567:89ac      some.address.somewhere some some.address\n",
};

struct Fixture
{
  static std::shared_ptr<DNSRecordContent> makeLocalhostRootDRC()
  {
    return DNSRecordContent::mastermake(QType::SOA, QClass::IN, "localhost. root 1 604800 86400 2419200 604800");
  }

  static std::shared_ptr<DNSRecordContent> makeLocalhostDRC()
  {
    return DNSRecordContent::mastermake(QType::NS, QClass::IN, "localhost.");
  }

  static std::shared_ptr<DNSRecordContent> makePtrDRC(const std::string& name)
  {
    return DNSRecordContent::mastermake(QType::PTR, QClass::IN, name);
  }

  void addDomainMapFixtureEntry(const std::string& name, const SyncRes::AuthDomain::records_t& records)
  {
    domainMapFixture[DNSName{name}] = SyncRes::AuthDomain{
      .d_records = records,
      .d_servers = {},
      .d_name = DNSName{name},
      .d_rdForward = false,
    };
  }

  void addDomainMapFixtureEntry(const std::string& name, const QType type, const std::string& address)
  {
    domainMapFixture[DNSName{name}] = SyncRes::AuthDomain{
      .d_records = {
        DNSRecord(name, DNSRecordContent::mastermake(type, QClass::IN, address), type),
        DNSRecord(name, makeLocalhostDRC(), QType::NS),
        DNSRecord(name, makeLocalhostRootDRC(), QType::SOA),
      },
      .d_servers = {},
      .d_name = DNSName{name},
      .d_rdForward = false,
    };
  }

  Fixture()
  {
    addDomainMapFixtureEntry("foo", QType::A, "192.168.0.1");
    addDomainMapFixtureEntry("bar", QType::A, "192.168.0.1");
    addDomainMapFixtureEntry("dupfoo", QType::A, "192.168.0.1");
    addDomainMapFixtureEntry(
      "1.0.168.192.in-addr.arpa",
      {
        DNSRecord("1.0.168.192.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("1.0.168.192.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("1.0.168.192.in-addr.arpa", makePtrDRC("foo."), QType::PTR),
        DNSRecord("1.0.168.192.in-addr.arpa", makePtrDRC("bar."), QType::PTR),
      });
    addDomainMapFixtureEntry("baz", QType::A, "192.168.0.2");
    addDomainMapFixtureEntry(
      "2.0.168.192.in-addr.arpa",
      {
        DNSRecord("2.0.168.192.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("2.0.168.192.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("2.0.168.192.in-addr.arpa", makePtrDRC("baz."), QType::PTR),
      });
    addDomainMapFixtureEntry("fancy", QType::A, "1.1.1.1");
    addDomainMapFixtureEntry(
      "1.1.1.1.in-addr.arpa",
      {
        DNSRecord("1.1.1.1.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("1.1.1.1.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("1.1.1.1.in-addr.arpa", makePtrDRC("fancy."), QType::PTR),
      });
    addDomainMapFixtureEntry("more.fancy", QType::A, "2.2.2.2");
    addDomainMapFixtureEntry(
      "2.2.2.2.in-addr.arpa",
      {
        DNSRecord("2.2.2.2.in-addr.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("2.2.2.2.in-addr.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("2.2.2.2.in-addr.arpa", makePtrDRC("more.fancy."), QType::PTR),
      });

    addDomainMapFixtureEntry("foo6", QType::AAAA, "2001:db8::567:89ab");
    addDomainMapFixtureEntry("bar6", QType::AAAA, "2001:db8::567:89ab");
    addDomainMapFixtureEntry("dupfoo6", QType::AAAA, "2001:db8::567:89ab");
    addDomainMapFixtureEntry(
      "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
      {
        DNSRecord("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makePtrDRC("foo6."), QType::PTR),
        DNSRecord("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makePtrDRC("bar6."), QType::PTR),
      });

    addDomainMapFixtureEntry("localhost", QType::AAAA, "::1");
    addDomainMapFixtureEntry("self", QType::AAAA, "::1");
    addDomainMapFixtureEntry(
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
      {
        DNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", makePtrDRC("localhost."), QType::PTR),
        DNSRecord("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", makePtrDRC("self."), QType::PTR),
      });

    addDomainMapFixtureEntry("some", QType::AAAA, "2001:db8::567:89ac");
    addDomainMapFixtureEntry("some.address.somewhere", QType::AAAA, "2001:db8::567:89ac");
    addDomainMapFixtureEntry("some.address", QType::AAAA, "2001:db8::567:89ac");
    addDomainMapFixtureEntry(
      "c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
      {
        DNSRecord("c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makeLocalhostDRC(), QType::NS),
        DNSRecord("c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makeLocalhostRootDRC(), QType::SOA),
        DNSRecord("c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makePtrDRC("some.address.somewhere."), QType::PTR),
        DNSRecord("c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makePtrDRC("some."), QType::PTR),
        DNSRecord("c.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", makePtrDRC("some.address."), QType::PTR),
      });
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

private:
  SyncRes::domainmap_t domainMapFixture{};
};

BOOST_FIXTURE_TEST_CASE(test_loading_etc_hosts, Fixture)
{
  auto log = g_slog->withName("config");

  auto domainMap = std::make_shared<SyncRes::domainmap_t>();
  std::vector<std::string> parts{};
  for (auto line : hostLines) {
    BOOST_REQUIRE(parseEtcHostsLine(parts, line));
    addForwardAndReverseLookupEntries(*domainMap, "", parts, log);
  }

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
}

BOOST_AUTO_TEST_SUITE_END()
