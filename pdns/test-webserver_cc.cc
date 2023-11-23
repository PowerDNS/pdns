#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include "webserver.hh"

BOOST_AUTO_TEST_SUITE(test_webserver_cc)

BOOST_AUTO_TEST_CASE(test_validURL)
{
  // We cannot test\x00 as embedded NULs are not handled by YaHTTP other than stopping the parsing
  const std::vector<std::pair<string, bool>> urls = {
    {"http://www.powerdns.com/?foo=123", true},
    {"http://ww.powerdns.com/?foo=%ff", true},
    {"http://\x01ww.powerdns.com/?foo=123", false},
    {"http://\xffwww.powerdns.com/?foo=123", false},
    {"http://www.powerdns.com/?foo=123\x01", false},
    {"http://www.powerdns.com/\x7f?foo=123", false},
    {"http://www.powerdns.com/\x80?foo=123", false},
    {"http://www.powerdns.com/?\xff", false},
    {"/?foo=123&bar", true},
    {"/?foo=%ff&bar", true},
    {"/?\x01foo=123", false},
    {"/?foo=123\x01", false},
    {"/\x7f?foo=123", false},
    {"/\x80?foo=123", false},
    {"/?\xff", false},
  };

  for (const auto& testcase : urls) {
    BOOST_CHECK_EQUAL(WebServer::validURL(testcase.first), testcase.second);
  }
}

BOOST_AUTO_TEST_SUITE_END();
