#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>

#include "test-common.hh"
#include "secpoll.hh"

BOOST_AUTO_TEST_SUITE(test_secpoll_cc)

bool checkBasicMessage1(const PDNSException &ex) {
  BOOST_CHECK_EQUAL(ex.reason, "Had empty answer on NOERROR RCODE");
  return true;
}

bool checkBasicMessage2(const PDNSException &ex) {
  BOOST_CHECK_EQUAL(ex.reason, "RCODE was not NOERROR but " + RCode::to_s(1));
  return true;
}

bool checkBasicMessage3(const PDNSException &ex) {
  BOOST_CHECK_EQUAL(ex.reason, "No TXT record found in response");
  return true;
}

bool checkBasicMessage4(const PDNSException &ex) {
  BOOST_CHECK(ex.reason.find("Could not parse status number: stoi") == 0);
  return true;
}

bool checkBasicMessage5(const PDNSException &ex) {
  BOOST_CHECK(ex.reason.find("Could not parse status number: stoi") == 0);
  return true;
}

BOOST_AUTO_TEST_CASE(test_secpoll_basic) {

  BOOST_CHECK(!isReleaseVersion(""));
  BOOST_CHECK(isReleaseVersion(".."));
  BOOST_CHECK(!isReleaseVersion("..."));


  int status = 0;
  std::string message;

  BOOST_CHECK_EXCEPTION(processSecPoll(0, std::vector<DNSRecord>(), status, message), PDNSException, checkBasicMessage1);
  BOOST_CHECK_EXCEPTION(processSecPoll(1, std::vector<DNSRecord>(), status, message), PDNSException, checkBasicMessage2);

  std::vector<DNSRecord> v;

  addRecordToList(v, DNSName("aname"), QType::A, "1.2.3.4");
  BOOST_CHECK_EXCEPTION(processSecPoll(0, v, status, message), PDNSException, checkBasicMessage3);

  v.clear();
  addRecordToList(v, DNSName("aname"), QType::TXT, "");
  BOOST_CHECK_EXCEPTION(processSecPoll(0, v, status, message), PDNSException, checkBasicMessage4);

  v.clear();
  addRecordToList(v, DNSName("aname"), QType::TXT, "1NOQUOTES");
  processSecPoll(0, v, status, message);
  BOOST_CHECK_EQUAL(status, 1);
  BOOST_CHECK_EQUAL(message, "");

  v.clear();
  addRecordToList(v, DNSName("aname"), QType::TXT, "\"1OK\"");
  processSecPoll(0, v, status, message);
  BOOST_CHECK_EQUAL(status, 1);
  BOOST_CHECK_EQUAL(message, "");

  v.clear();
  addRecordToList(v, DNSName("aname"), QType::TXT, "\"1 OK\"");
  processSecPoll(0, v, status, message);
  BOOST_CHECK_EQUAL(status, 1);
  BOOST_CHECK_EQUAL(message, "OK");

  v.clear();
  addRecordToList(v, DNSName("aname"), QType::TXT, "\"X OK\"");
  BOOST_CHECK_EXCEPTION(processSecPoll(0, v, status, message), PDNSException, checkBasicMessage5);

}
BOOST_AUTO_TEST_SUITE_END();
