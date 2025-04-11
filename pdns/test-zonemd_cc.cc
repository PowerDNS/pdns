#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "zonemd.hh"
#include "zoneparser-tng.hh"

BOOST_AUTO_TEST_SUITE(test_zonemd_cc)

static void testZoneMD(const std::string& zone, const std::string& file, bool ex, bool done, bool ok)
{
  const char* p = std::getenv("SRCDIR");
  if (!p) {
    p = ".";
  }
  ZoneName zonename(zone);
  std::ostringstream pathbuf;
  pathbuf << p << "/../regression-tests/zones/" + file;
  ZoneParserTNG zpt(pathbuf.str(), zonename);

  bool validationDone = false, validationOK = false;

  try {
    auto zonemd = pdns::ZoneMD(zonename);
    zonemd.readRecords(zpt);
    zonemd.verify(validationDone, validationOK);
  }
  catch (const PDNSException& e) {
    BOOST_CHECK(ex);
  }
  catch (const std::exception& e) {
    BOOST_CHECK(ex);
  }

  BOOST_CHECK(validationDone == done);
  BOOST_CHECK(validationOK == ok);
}

BOOST_AUTO_TEST_CASE(test_zonemd1)
{
  testZoneMD("example", "zonemd1.zone", false, true, true);
}

BOOST_AUTO_TEST_CASE(test_zonemd2)
{
  testZoneMD("example", "zonemd2.zone", false, true, true);
}

BOOST_AUTO_TEST_CASE(test_zonemd3)
{
  testZoneMD("example", "zonemd3.zone", false, true, true);
}

BOOST_AUTO_TEST_CASE(test_zonemd4)
{
  testZoneMD("uri.arpa", "zonemd4.zone", false, true, true);
}

BOOST_AUTO_TEST_CASE(test_zonemd5)
{
  testZoneMD("root-servers.net", "zonemd5.zone", false, true, true);
}

BOOST_AUTO_TEST_CASE(test_zonemd6)
{
  testZoneMD("example", "zonemd-invalid.zone", false, true, false);
}

BOOST_AUTO_TEST_CASE(test_zonemd7)
{
  testZoneMD("example", "zonemd-nozonemd.zone", false, false, false);
}

BOOST_AUTO_TEST_CASE(test_zonemd8)
{
  testZoneMD("example", "zonemd-allunsup.zone", false, false, false);
}

BOOST_AUTO_TEST_CASE(test_zonemd9)
{
  testZoneMD("example", "zonemd-sha512.zone", false, true, true);
}

BOOST_AUTO_TEST_CASE(test_zonemd10)
{
  testZoneMD("example", "zonemd-serialmismatch.zone", false, false, false);
}

BOOST_AUTO_TEST_CASE(test_zonemd11)
{
  testZoneMD("example", "zonemd-duplicate.zone", false, false, false);
}

BOOST_AUTO_TEST_CASE(test_zonemd12)
{
  testZoneMD("root-servers.net", "zonemd-syntax.zone", true, false, false);
}

BOOST_AUTO_TEST_CASE(test_zonemd13)
{
  testZoneMD("xxx", "zonemd1.zone", false, false, false);
}

BOOST_AUTO_TEST_SUITE_END()
