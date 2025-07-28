#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include <stdio.h>

#include "rec-zonetocache.hh"
#include "recursor_cache.hh"
#include "test-syncres_cc.hh"

extern unique_ptr<MemRecursorCache> g_recCache;

BOOST_AUTO_TEST_SUITE(rec_zonetocache)

// A piece of the root zone
const std::string zone = ".	86400	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2021080900 1800 900 604800 86400\n"
                         ".	518400	IN	NS	a.root-servers.net.\n"
                         ".	518400	IN	NS	b.root-servers.net.\n"
                         ".	518400	IN	NS	c.root-servers.net.\n"
                         ".	518400	IN	NS	d.root-servers.net.\n"
                         ".	518400	IN	NS	e.root-servers.net.\n"
                         ".	518400	IN	NS	f.root-servers.net.\n"
                         ".	518400	IN	NS	g.root-servers.net.\n"
                         ".	518400	IN	NS	h.root-servers.net.\n"
                         ".	518400	IN	NS	i.root-servers.net.\n"
                         ".	518400	IN	NS	j.root-servers.net.\n"
                         ".	518400	IN	NS	k.root-servers.net.\n"
                         ".	518400	IN	NS	l.root-servers.net.\n"
                         ".	518400	IN	NS	m.root-servers.net.\n"
                         ".	172800	IN	DNSKEY	256 3 8 AwEAAbDEyqdwu2fqAwinPCFwALUCWfYYaLrNhnOrMxDorLBYMipEE1btlK1XnigTRMeb0YQ8/LCopb3CN73hYDhCHFsNk+GtukBB+gWLcg+2FZXbhLXIheQm8x2VfOHy2yYQG+18wjx3HY9Mj/ZEhXbZNrDMvpFKKVihWXa0/cHNg4ZcIHD9KkMlKzK+my1K/vz8fq5cFCFOu7wgM+kKbOikdcRBm7Uf/wRXZItFg2uhUijUb56gEN8uCUgmuEw6wQ5ZBuR7UT/FLyyAUeAH87oxF4im2DXK6J+JA7IAs2UHJ16uTqvdserUU8NIosislaXIZCvz+NTDb3SJcxs6bvCikeU= ;{id = 26838 (zsk), size = 2048b}\n"
                         ".	172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU= ;{id = 20326 (ksk), size = 2048b}\n"
                         ".	86400	IN	NSEC	aaa. NS SOA RRSIG NSEC DNSKEY \n"
                         "aaa.	172800	IN	NS	ns1.dns.nic.aaa.\n"
                         "aaa.	172800	IN	NS	ns2.dns.nic.aaa.\n"
                         "aaa.	172800	IN	NS	ns3.dns.nic.aaa.\n"
                         "aaa.	172800	IN	NS	ns4.dns.nic.aaa.\n"
                         "aaa.	172800	IN	NS	ns5.dns.nic.aaa.\n"
                         "aaa.	172800	IN	NS	ns6.dns.nic.aaa.\n"
                         "aaa.	86400	IN	DS	1657 8 1 0b0d56361ce62118537e07a680e9582f5f5fa129\n"
                         "aaa.	86400	IN	DS	1657 8 2 9d6bae62219231c99faa479716b6e4619330ce8206670aea6c1673a055dc3af2\n"
                         "aaa.	86400	IN	NSEC	aarp. NS DS RRSIG NSEC \n"
                         "ns1.dns.nic.aaa.	172800	IN	A	156.154.144.2\n"
                         "ns1.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1071::2\n"
                         "ns2.dns.nic.aaa.	172800	IN	A	156.154.145.2\n"
                         "ns2.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1072::2\n"
                         "ns3.dns.nic.aaa.	172800	IN	A	156.154.159.2\n"
                         "ns3.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1073::2\n"
                         "ns4.dns.nic.aaa.	172800	IN	A	156.154.156.2\n"
                         "ns4.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1074::2\n"
                         "ns5.dns.nic.aaa.	172800	IN	A	156.154.157.2\n"
                         "ns5.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1075::2\n"
                         "ns6.dns.nic.aaa.	172800	IN	A	156.154.158.2\n"
                         "ns6.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1076::2\n";

const std::string goodZONEMD = ".	86400	IN	ZONEMD	2021080900 1 1 dad404980c735405fc2172a5e4f00a6914e0e9937bc7085875b5eda3b3a14b088845c67efd179f7d19d7cd054f9f1e6f\n";
const std::string badZONEMD = ".	86400	IN	ZONEMD	2021080900 1 1 0ad404980c735405fc2172a5e4f00a6914e0e9937bc7085875b5eda3b3a14b088845c67efd179f7d19d7cd054f9f1e6f\n";

const std::string zoneWithBadZONEMD = zone + badZONEMD;
const std::string zoneWithGoodZONEMD = zone + goodZONEMD;

static void zonemdTest(const std::string& lines, pdns::ZoneMD::Config mode, pdns::ZoneMD::Config dnssec, size_t expectedCacheSize)
{
  char temp[] = "/tmp/ztcXXXXXXXXXX";
  int fd = mkstemp(temp);
  BOOST_REQUIRE(fd > 0);
  FILE* fp = fdopen(fd, "w");
  BOOST_REQUIRE(fp != nullptr);
  size_t written = fwrite(lines.data(), 1, lines.length(), fp);
  BOOST_REQUIRE(written == lines.length());
  BOOST_REQUIRE(fclose(fp) == 0);

  RecZoneToCache::Config config{".", "file", {temp}, ComboAddress(), TSIGTriplet()};
  config.d_refreshPeriod = 0;
  config.d_retryOnError = 0;
  config.d_zonemd = mode;
  config.d_dnssec = dnssec;

  // Start with a new, empty cache
  g_recCache = std::make_unique<MemRecursorCache>();
  BOOST_CHECK_EQUAL(g_recCache->size(), 0U);
  RecZoneToCache::State state;
  RecZoneToCache::ZoneToCache(config, state);
  unlink(temp);

  BOOST_CHECK_EQUAL(g_recCache->size(), expectedCacheSize);

  if (expectedCacheSize > 0) {
    std::vector<DNSRecord> retrieved;
    time_t now = time(nullptr);
    ComboAddress who;
    BOOST_CHECK_GT(g_recCache->get(now, DNSName("."), QType::SOA, MemRecursorCache::RequireAuth, &retrieved, who), 0);
    // not auth
    BOOST_CHECK_LT(g_recCache->get(now, DNSName("aaa."), QType::NS, MemRecursorCache::RequireAuth, &retrieved, who), 0);
    // auth
    BOOST_CHECK_GT(g_recCache->get(now, DNSName("aaa."), QType::NS, MemRecursorCache::None, &retrieved, who), 0);
  }
}

BOOST_AUTO_TEST_CASE(test_zonetocache)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);
  g_log.setLoglevel(Logger::Critical);
  g_log.toConsole(Logger::Critical);
  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  zonemdTest(zone, pdns::ZoneMD::Config::Ignore, pdns::ZoneMD::Config::Ignore, 17U);
  zonemdTest(zone, pdns::ZoneMD::Config::Validate, pdns::ZoneMD::Config::Ignore, 17U);
  zonemdTest(zone, pdns::ZoneMD::Config::Require, pdns::ZoneMD::Config::Ignore, 0U);
  zonemdTest(zone, pdns::ZoneMD::Config::Ignore, pdns::ZoneMD::Config::Validate, 0U);

  zonemdTest(zoneWithGoodZONEMD, pdns::ZoneMD::Config::Ignore, pdns::ZoneMD::Config::Ignore, 18U);
  zonemdTest(zoneWithGoodZONEMD, pdns::ZoneMD::Config::Validate, pdns::ZoneMD::Config::Ignore, 18U);
  zonemdTest(zoneWithGoodZONEMD, pdns::ZoneMD::Config::Require, pdns::ZoneMD::Config::Ignore, 18U);
  zonemdTest(zoneWithGoodZONEMD, pdns::ZoneMD::Config::Require, pdns::ZoneMD::Config::Validate, 0U);

  zonemdTest(zoneWithBadZONEMD, pdns::ZoneMD::Config::Ignore, pdns::ZoneMD::Config::Ignore, 18U);
  zonemdTest(zoneWithBadZONEMD, pdns::ZoneMD::Config::Validate, pdns::ZoneMD::Config::Ignore, 0U);
  zonemdTest(zoneWithBadZONEMD, pdns::ZoneMD::Config::Require, pdns::ZoneMD::Config::Ignore, 0U);
  zonemdTest(zoneWithBadZONEMD, pdns::ZoneMD::Config::Ignore, pdns::ZoneMD::Config::Require, 0U);
}

// Example from https://github.com/verisign/zonemd-test-cases/blob/master/zones/20-generic-zonemd/example.zone
const std::string genericTest = "example.	86400	IN	NS	ns.example.\n"
                                "example.	86400	IN	SOA	ns.example. admin.example. 2018031900 1800 900 604800 86400\n"
                                "example.	86400	IN	TYPE63  \\# 54 7848b91c01018ee54f64ce0d57fd70e1a4811a9ca9e849e2e50cb598edf3ba9c2a58625335c1f966835f0d4338d9f78f557227d63bf6\n"
                                "ns.example.	3600	IN	A	127.0.0.1\n";

const std::string genericBadTest = "example.	86400	IN	NS	ns.example.\n"
                                   "example.	86400	IN	SOA	ns.example. admin.example. 2018031900 1800 900 604800 86400\n"
                                   "example.	86400	IN	TYPE63  \\# 54 8848b91c01018ee54f64ce0d57fd70e1a4811a9ca9e849e2e50cb598edf3ba9c2a58625335c1f966835f0d4338d9f78f557227d63bf6\n"
                                   "ns.example.	3600	IN	A	127.0.0.1\n";

static void zonemdGenericTest(const std::string& lines, pdns::ZoneMD::Config mode, pdns::ZoneMD::Config dnssec, size_t expectedCacheSize)
{
  char temp[] = "/tmp/ztcXXXXXXXXXX";
  int fd = mkstemp(temp);
  BOOST_REQUIRE(fd > 0);
  FILE* fp = fdopen(fd, "w");
  BOOST_REQUIRE(fp != nullptr);
  size_t written = fwrite(lines.data(), 1, lines.length(), fp);
  BOOST_REQUIRE(written == lines.length());
  BOOST_REQUIRE(fclose(fp) == 0);

  RecZoneToCache::Config config{"example.", "file", {temp}, ComboAddress(), TSIGTriplet()};
  config.d_refreshPeriod = 0;
  config.d_retryOnError = 0;
  config.d_zonemd = mode;
  config.d_dnssec = dnssec;

  // Start with a new, empty cache
  g_recCache = std::make_unique<MemRecursorCache>();
  BOOST_CHECK_EQUAL(g_recCache->size(), 0U);
  RecZoneToCache::State state;
  RecZoneToCache::ZoneToCache(config, state);
  unlink(temp);

  BOOST_CHECK_EQUAL(g_recCache->size(), expectedCacheSize);

  if (expectedCacheSize > 0) {
    std::vector<DNSRecord> retrieved;
    time_t now = time(nullptr);
    ComboAddress who;
    BOOST_CHECK_GT(g_recCache->get(now, DNSName("example."), QType::SOA, true, &retrieved, who), 0);
    BOOST_CHECK_GT(g_recCache->get(now, DNSName("example."), QType::NS, true, &retrieved, who), 0);
    BOOST_CHECK_GT(g_recCache->get(now, DNSName("example."), QType::ZONEMD, true, &retrieved, who), 0);
    BOOST_CHECK_GT(g_recCache->get(now, DNSName("ns.example."), QType::A, true, &retrieved, who), 0);
  }
}

BOOST_AUTO_TEST_CASE(test_zonetocachegeneric)
{
  SyncRes::setDomainMap(std::make_shared<SyncRes::domainmap_t>());
  g_log.setLoglevel(Logger::Critical);
  g_log.toConsole(Logger::Critical);
  zonemdGenericTest(genericTest, pdns::ZoneMD::Config::Require, pdns::ZoneMD::Config::Ignore, 4U);
  zonemdGenericTest(genericBadTest, pdns::ZoneMD::Config::Require, pdns::ZoneMD::Config::Ignore, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
