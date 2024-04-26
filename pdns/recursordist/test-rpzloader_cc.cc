#define BOOST_TEST_RPZ_LOADER
#define BOOST_TEST_RPZ_LOADER
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <array>

#include "arguments.hh"
#include "rpzloader.hh"
#include "syncres.hh"

#include <boost/test/unit_test.hpp>

// Provide stubs for some symbols
bool g_logRPZChanges{false};

BOOST_AUTO_TEST_SUITE(rpzloader_cc)

BOOST_AUTO_TEST_CASE(test_rpz_loader)
{

  string tests[][2] = {
    {"32.3.2.168.192", "192.168.2.3/32"},
    {"27.73.2.168.192", "192.168.2.64/27"},
    {"24.0.2.168.192", "192.168.2.0/24"},
    {"128.57.zz.1.0.db8.2001", "2001:db8:0:1::57/128"},
    {"48.zz.1.0.db8.2001", "2001:db8::/48"},
    {"128.5.C0A8.FFFF.0.1.0.db8.2001", "2001:db8:0:1:0:ffff:c0a8:5/128"},

    {"21.0.248.44.5", "5.44.248.0/21"},
    {"64.0.0.0.0.0.1.0.0.", "0:0:1::/64"},
    {"64.zz.2.0.0", "0:0:2::/64"},
    {"80.0.0.0.1.0.0.0.0", "::1:0:0:0/80"},
    {"80.0.0.0.1.zz", "::1:0:0:0/80"}};

  for (auto& test : tests) {
    Netmask n = makeNetmaskFromRPZ(DNSName(test[0]));
    BOOST_CHECK_EQUAL(n.toString(), test[1]);
  }
}

static string makeFile(const string& lines)
{
  std::array<char, 20> temp{"/tmp/rpzXXXXXXXXXX"};
  int fileDesc = mkstemp(temp.data());
  BOOST_REQUIRE(fileDesc > 0);
  auto filePtr = pdns::UniqueFilePtr(fdopen(fileDesc, "w"));
  BOOST_REQUIRE(filePtr);
  size_t written = fwrite(lines.data(), 1, lines.length(), filePtr.get());
  BOOST_REQUIRE(written == lines.length());
  BOOST_REQUIRE(fflush(filePtr.get()) == 0);
  return temp.data();
}

BOOST_AUTO_TEST_CASE(load_rpz_ok)
{
  const string lines = "\n"
                       "$ORIGIN rpz.example.net.\n"
                       "$TTL 1H\n"
                       "@                   SOA LOCALHOST. named-mgr.example.net. (\n"
                       "                                        1 1h 15m 30d 2h)\n"
                       "                    NS LOCALHOST.\n"
                       "\n"
                       "; QNAME policy records.\n"
                       "; There are no periods (.) after the relative owner names.\n"
                       "nxdomain.example.com        CNAME   .       ; NXDOMAIN policy\n"
                       "nodata.example.com          CNAME   *.      ; NODATA policy\n"
                       "\n"
                       "; Redirect to walled garden\n"
                       "bad.example.com             A       10.0.0.1\n"
                       "                            AAAA    2001:db8::1\n"
                       "\n"
                       "; Rewrite all names inside \"AZONE.EXAMPLE.COM\"\n"
                       "; except \"OK.AZONE.EXAMPLE.COM\"\n"
                       "*.azone.example.com         CNAME   garden.example.net.\n"
                       "ok.azone.example.com        CNAME   rpz-passthru.\n"
                       "\n"
                       "; Redirect \"BZONE.EXAMPLE.COM\" and \"X.BZONE.EXAMPLE.COM\"\n"
                       "; to \"BZONE.EXAMPLE.COM.GARDEN.EXAMPLE.NET\" and\n"
                       "; \"X.BZONE.EXAMPLE.COM.GARDEN.EXAMPLE.NET\", respectively.\n"
                       "bzone.example.com           CNAME   *.garden.example.net.\n"
                       "*.bzone.example.com         CNAME   *.garden.example.net.\n"
                       "\n"
                       "; Rewrite all answers containing addresses in 192.0.2.0/24,\n"
                       "; except 192.0.2.1\n"
                       "24.0.2.0.192.rpz-ip         CNAME   .\n"
                       "32.1.2.0.192.rpz-ip         CNAME   rpz-passthru.\n"
                       "\n"
                       "; Rewrite to NXDOMAIN all responses for domains for which\n"
                       "; \"NS.EXAMPLE.COM\" is an authoritative DNS server for that domain\n"
                       "; or any of its ancestors, or that have an authoritative server\n"
                       "; in 2001:db8::/32\n"
                       "ns.example.com.rpz-nsdname  CNAME   .\n"
                       "32.zz.db8.2001.rpz-nsip     CNAME   .\n"
                       "\n"
                       "; Local Data can include many record types\n"
                       "25.128.2.0.192.rpz-ip       A       172.16.0.1\n"
                       "25.128.2.0.192.rpz-ip       A       172.16.0.2\n"
                       "25.128.2.0.192.rpz-ip       A       172.16.0.3\n"
                       "25.128.2.0.192.rpz-ip       MX      10 mx1.example.com\n"
                       "25.128.2.0.192.rpz-ip       MX      20 mx2.example.com\n"
                       "25.128.2.0.192.rpz-ip       TXT     \"Contact Central Services\"\n"
                       "25.128.2.0.192.rpz-ip       TXT     \"Your system is infected.\"\n";

  auto rpz = makeFile(lines);

  ::arg().set("max-generate-steps") = "1";
  ::arg().set("max-include-depth") = "20";
  auto zone = std::make_shared<DNSFilterEngine::Zone>();
  auto soa = loadRPZFromFile(rpz, zone, boost::none, false, 3600);
  unlink(rpz.c_str());

  BOOST_CHECK_EQUAL(soa->d_st.serial, 1U);
  BOOST_CHECK_EQUAL(zone->getDomain(), DNSName("rpz.example.net."));
  BOOST_CHECK_EQUAL(zone->size(), 12U);
}

BOOST_AUTO_TEST_CASE(load_rpz_dups)
{
  const string lines = "\n"
                       "$TTL 300\n"
                       "\n"
                       "@              IN SOA  need.to.know.only.  hostmaster.spamhaus.org. (\n"
                       "                       1000000000 ; Serial number\n"
                       "                       60         ; Refresh every 1 minutes\n"
                       "                       60         ; Retry every minute\n"
                       "                       432000     ; Expire in 5 days\n"
                       "                       60 )       ; negative caching ttl 1 minute\n"
                       "               IN NS   LOCALHOST.\n"
                       "qqq.powerdns.net   CNAME .\n"
                       "qqq.powerdns.net   IN A 3.4.5.6\n";

  auto rpz = makeFile(lines);

  ::arg().set("max-generate-steps") = "1";
  ::arg().set("max-include-depth") = "20";
  auto zone = std::make_shared<DNSFilterEngine::Zone>();

  BOOST_CHECK_THROW(loadRPZFromFile(rpz, zone, boost::none, false, 3600),
                    std::runtime_error);
  unlink(rpz.c_str());
}

BOOST_AUTO_TEST_CASE(load_rpz_dups_allow)
{
  const string lines = "\n"
                       "$TTL 300\n"
                       "\n"
                       "@              IN SOA  need.to.know.only.  hostmaster.powerdns.org. (\n"
                       "                       1000000000 ; Serial number\n"
                       "                       60         ; Refresh every 1 minutes\n"
                       "                       60         ; Retry every minute\n"
                       "                       432000     ; Expire in 5 days\n"
                       "                       60 )       ; negative caching ttl 1 minute\n"
                       "               IN NS   LOCALHOST.\n"
                       "qqq.powerdns.net   CNAME .\n"
                       "qqq.powerdns.net   CNAME rpz-passthru\n";

  auto rpz = makeFile(lines);

  ::arg().set("max-generate-steps") = "1";
  ::arg().set("max-include-depth") = "20";
  auto zone = std::make_shared<DNSFilterEngine::Zone>();
  zone->setIgnoreDuplicates(true);
  auto soa = loadRPZFromFile(rpz, zone, boost::none, false, 3600);
  unlink(rpz.c_str());
  BOOST_CHECK_EQUAL(soa->d_st.serial, 1000000000U);
  BOOST_CHECK_EQUAL(zone->getDomain(), DNSName("."));
  BOOST_CHECK_EQUAL(zone->size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
