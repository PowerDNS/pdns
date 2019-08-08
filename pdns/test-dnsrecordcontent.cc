#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "dnsrecords.hh"
#include "iputils.hh"

BOOST_AUTO_TEST_SUITE(test_dnsrecordcontent)

BOOST_AUTO_TEST_CASE(test_equality) {
  ComboAddress ip("1.2.3.4"), ip2("10.0.0.1"), ip6("::1");
  ARecordContent a1(ip), a2(ip), a3(ip2);
  AAAARecordContent aaaa(ip6), aaaa1(ip6);
  
  BOOST_CHECK(a1==a2);
  BOOST_CHECK(!(a1==a3));

  BOOST_CHECK(aaaa == aaaa1);


  auto rec1=DNSRecordContent::mastermake(QType::A, 1, "192.168.0.1");
  auto rec2=DNSRecordContent::mastermake(QType::A, 1, "192.168.222.222");
  auto rec3=DNSRecordContent::mastermake(QType::AAAA, 1, "::1");
  auto recMX=DNSRecordContent::mastermake(QType::MX, 1, "25 smtp.powerdns.com");
  auto recMX2=DNSRecordContent::mastermake(QType::MX, 1, "26 smtp.powerdns.com");
  auto recMX3=DNSRecordContent::mastermake(QType::MX, 1, "26 SMTP.powerdns.com");
  BOOST_CHECK(!(*rec1==*rec2));
  BOOST_CHECK(*rec1==*rec1);
  BOOST_CHECK(*rec3==*rec3);

  BOOST_CHECK(*recMX==*recMX);
  BOOST_CHECK(*recMX2==*recMX3);
  BOOST_CHECK(!(*recMX==*recMX3));
  
  
  BOOST_CHECK(!(*rec1==*rec3));

  NSRecordContent ns1(DNSName("ns1.powerdns.com")), ns2(DNSName("NS1.powerdns.COM")), ns3(DNSName("powerdns.net"));
  BOOST_CHECK(ns1==ns2);
  BOOST_CHECK(!(ns1==ns3));
}

BOOST_AUTO_TEST_SUITE_END()
