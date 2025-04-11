#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/iostreams/device/file.hpp>
#include "dns.hh"
#include "zoneparser-tng.hh"
#include "dnsrecords.hh"
#include "dnsname.hh"
#include <fstream>
#include <cstdlib>

BOOST_AUTO_TEST_SUITE(test_zoneparser_tng_cc)

BOOST_AUTO_TEST_CASE(test_tng_record_types) {
  std::ostringstream pathbuf;
  const char* p = std::getenv("SRCDIR");
  if(!p)
    p = ".";
  pathbuf << p << "/../regression-tests/zones/unit.test";
  ZoneParserTNG zp(pathbuf.str(), ZoneName("unit.test"));
  DNSResourceRecord rr;

  ifstream ifs(pathbuf.str());

  while(zp.get(rr)) {
    // make sure these concur.
    std::string host, type, data;
    unsigned int ttl;
    std::getline(ifs, host, ' ');
    std::getline(ifs, type, ' ');
    pdns::checked_stoi_into(ttl, type);
    std::getline(ifs, type, ' ');
    std::getline(ifs, type, ' ');
    std::getline(ifs, data, '\n');
    // see if these agree
    BOOST_CHECK_EQUAL(rr.qname.toString(), host);
    BOOST_CHECK_EQUAL(rr.ttl, ttl);
    BOOST_CHECK_EQUAL(rr.qtype.toString(), type);
    if (rr.qtype == QType::SOA)
      continue; // FIXME400 remove trailing dots from data
    if (*(rr.content.rbegin()) != '.' && *(data.rbegin()) == '.')
      BOOST_CHECK_EQUAL(rr.content, std::string(data.begin(),data.end()-1));
    else
      BOOST_CHECK_EQUAL(rr.content, data);
  }
}

BOOST_AUTO_TEST_CASE(test_tng_record_generate) {
  std::ostringstream pathbuf;
  const char* p = std::getenv("SRCDIR");
  if(!p)
    p = ".";
  pathbuf << p << "/../regression-tests/zones/unit2.test";

  {
    /* simple case */
    ZoneParserTNG zp(pathbuf.str(), ZoneName("unit2.test"));

    const vector<string> expected = {
      "0.01.0003.000005.00000007.unit2.test.",
      "1.02.0004.000006.00000008.unit2.test.",
      "2.03.0005.000007.00000009.unit2.test.",
      "3.04.0006.000008.0000000a.unit2.test.",
      "4.05.0007.000009.0000000b.unit2.test.",
      "5.06.0008.00000A.0000000c.unit2.test.",
      "6.07.0009.00000B.0000000d.unit2.test.",
      "7.10.0010.00000C.0000000e.unit2.test.",
      "8.11.0011.00000D.0000000f.unit2.test.",
      "9.12.0012.00000E.00000010.unit2.test.",
      "10.13.0013.00000F.00000011.unit2.test.",
      "11.14.0014.000010.00000012.unit2.test.",
      "12.15.0015.000011.00000013.unit2.test.",
      "13.16.0016.000012.00000014.unit2.test.",
      "14.17.0017.000013.00000015.unit2.test.",
      "15.20.0018.000014.00000016.unit2.test.",
      "16.21.0019.000015.00000017.unit2.test."
    };

    for (auto const & exp : expected) {
      DNSResourceRecord rr;
      zp.get(rr);
      BOOST_CHECK_EQUAL(rr.qname.toString(), exp);
      BOOST_CHECK_EQUAL(rr.ttl, 86400U);
      BOOST_CHECK_EQUAL(rr.qclass, 1U);
      BOOST_CHECK_EQUAL(rr.qtype.toString(), "A");
      BOOST_CHECK_EQUAL(rr.content, "1.2.3.4");
    }
  }

  {
    /* GENERATE with a step of 2, and the template radix defaulting to 'd' */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 0-4/2 $.${1,2,o}.${3,4}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("unit2.test"));

    const vector<string> expected = {
      "0.01.0003.000005.00000007.unit2.test.",
      "2.03.0005.000007.00000009.unit2.test.",
      "4.05.0007.000009.0000000b.unit2.test.",
    };

    for (auto const & exp : expected) {
      DNSResourceRecord rr;
      zp.get(rr);
      BOOST_CHECK_EQUAL(rr.qname.toString(), exp);
      BOOST_CHECK_EQUAL(rr.ttl, 86400U);
      BOOST_CHECK_EQUAL(rr.qclass, 1U);
      BOOST_CHECK_EQUAL(rr.qtype.toString(), "A");
      BOOST_CHECK_EQUAL(rr.content, "1.2.3.4");
    }
    {
      DNSResourceRecord rr;
      BOOST_CHECK(!zp.get(rr));
    }
  }

  {
    /* GENERATE with a larger initial counter and a large stop */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 4294967294-4294967295/2 $	86400	IN	A 1.2.3.4"}), ZoneName("unit2.test"));

    const vector<string> expected = {
      "4294967294.unit2.test.",
    };

    for (auto const & exp : expected) {
      DNSResourceRecord rr;
      zp.get(rr);
      BOOST_CHECK_EQUAL(rr.qname.toString(), exp);
      BOOST_CHECK_EQUAL(rr.ttl, 86400U);
      BOOST_CHECK_EQUAL(rr.qclass, 1U);
      BOOST_CHECK_EQUAL(rr.qtype.toString(), "A");
      BOOST_CHECK_EQUAL(rr.content, "1.2.3.4");
    }
    {
      DNSResourceRecord rr;
      BOOST_CHECK(!zp.get(rr));
    }
  }

  {
    /* test invalid generate parameters: stop greater than start */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 5-4 $.${1,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), std::exception);
  }

  {
    /* test invalid generate parameters: no stop */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 5 $.${1,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), std::exception);
  }

  {
    /* test invalid generate parameters: invalid step */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 0-4/0 $.${1,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), std::exception);
  }

  {
    /* test invalid generate parameters: negative counter */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE -1-4/1 $.${1,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), std::exception);
  }
  {
    /* test invalid generate parameters: counter out of bounds */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 4294967296-4/1 $.${1,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), std::exception);
  }

  {
    /* test invalid generate parameters: negative stop */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 0--4/1 $.${1,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), std::exception);
  }

  {
    /* test invalid generate parameters: stop out of bounds */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 0-4294967296/1 $.${1,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), std::exception);
  }

  {
    /* test invalid generate parameters: negative step */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 0-4/-1 $.${1,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), std::exception);
  }

  {
    /* test invalid generate parameters: no offset */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 0-4/1 $.${}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), PDNSException);
  }

  {
    /* test invalid generate parameters: invalid offset */
    ZoneParserTNG zp(std::vector<std::string>({"$GENERATE 0-4/1 $.${a,2,o}.${3,4,d}.${5,6,X}.${7,8,x}	86400	IN	A 1.2.3.4"}), ZoneName("test"));
    DNSResourceRecord rr;
    BOOST_CHECK_THROW(zp.get(rr), PDNSException);
  }
}

BOOST_AUTO_TEST_CASE(test_tng_upgrade) {
  ZoneParserTNG zp(std::vector<std::string>({"foo.test. 86400 IN TYPE1 \\# 4 c0000304"}), ZoneName("test"), true);
  DNSResourceRecord rr;
  zp.get(rr);

  BOOST_CHECK_EQUAL(rr.qtype.toString(), QType(QType::A).toString());
  BOOST_CHECK_EQUAL(rr.content, std::string("192.0.3.4"));
}

BOOST_AUTO_TEST_SUITE_END();
