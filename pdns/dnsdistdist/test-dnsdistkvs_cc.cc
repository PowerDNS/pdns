
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist-kvs.hh"

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
static const ComboAddress v4ToMask("203.0.113.255");
static const ComboAddress v6ToMask("2001:db8:ff:ff:ff:ff:ff:ff");

static void doKVSChecks(std::unique_ptr<KeyValueStore>& kvs, const ComboAddress& lc, const ComboAddress& rem, const DNSQuestion& dq, const DNSName& plaintextDomain)
{
  /* source IP */
  {
    auto lookupKey = make_unique<KeyValueLookupKeySourceIP>(32, 128, false);
    std::string value;
    /* local address is not in the db, remote is */
    BOOST_CHECK_EQUAL(kvs->getValue(std::string(reinterpret_cast<const char*>(&lc.sin4.sin_addr.s_addr), sizeof(lc.sin4.sin_addr.s_addr)), value), false);
    BOOST_CHECK_EQUAL(kvs->keyExists(std::string(reinterpret_cast<const char*>(&lc.sin4.sin_addr.s_addr), sizeof(lc.sin4.sin_addr.s_addr))), false);
    BOOST_CHECK(kvs->keyExists(std::string(reinterpret_cast<const char*>(&dq.ids.origRemote.sin4.sin_addr.s_addr), sizeof(dq.ids.origRemote.sin4.sin_addr.s_addr))));

    auto keys = lookupKey->getKeys(dq);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), true);
      BOOST_CHECK_EQUAL(value, "this is the value for the remote addr");
    }
  }

  /* masked source IP */
  {
    auto lookupKey = make_unique<KeyValueLookupKeySourceIP>(25, 65, false);

    auto keys = lookupKey->getKeys(v4ToMask);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      std::string value;
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), true);
      BOOST_CHECK_EQUAL(value, "this is the value for the masked v4 addr");
    }

    keys = lookupKey->getKeys(v6ToMask);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      std::string value;
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), true);
      BOOST_CHECK_EQUAL(value, "this is the value for the masked v6 addr");
    }
  }

  /* source IP + port */
  {
    auto lookupKey = make_unique<KeyValueLookupKeySourceIP>(32, 128, true);
    std::string value;
    BOOST_CHECK(kvs->keyExists(std::string(reinterpret_cast<const char*>(&rem.sin4.sin_addr.s_addr), sizeof(rem.sin4.sin_addr.s_addr)) + std::string(reinterpret_cast<const char*>(&rem.sin4.sin_port), sizeof(rem.sin4.sin_port))));

    auto keys = lookupKey->getKeys(dq);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), true);
      BOOST_CHECK_EQUAL(value, "this is the value for the remote addr + port");
    }
  }

  const DNSName subdomain = DNSName("sub") + dq.ids.qname;
  const DNSName notPDNS("not-powerdns.com.");

  /* qname match, in wire format */
  {
    std::string value;
    auto lookupKey = make_unique<KeyValueLookupKeyQName>(true);
    auto keys = lookupKey->getKeys(dq);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), true);
      BOOST_CHECK_EQUAL(value, "this is the value for the qname");
    }

    /* other domain, should not match */
    keys = lookupKey->getKeys(notPDNS);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }

    /* subdomain, should not match */
    keys = lookupKey->getKeys(subdomain);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }

    /* this domain was inserted in plaintext, the wire format lookup should not match */
    keys = lookupKey->getKeys(plaintextDomain);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }
  }

  /* qname match, in plain text */
  {
    std::string value;
    auto lookupKey = make_unique<KeyValueLookupKeyQName>(false);
    auto keys = lookupKey->getKeys(dq);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }

    /* other domain, should not match */
    keys = lookupKey->getKeys(notPDNS);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }

    /* subdomain, should not match */
    keys = lookupKey->getKeys(subdomain);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }

    /* this domain was inserted in plaintext, so it should match */
    keys = lookupKey->getKeys(plaintextDomain);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), true);
      BOOST_CHECK_EQUAL(value, "this is the value for the plaintext domain");
    }
  }

  /* suffix match in wire format */
  {
    auto lookupKey = make_unique<KeyValueLookupKeySuffix>(0, true);
    auto keys = lookupKey->getKeys(dq);
    BOOST_CHECK_EQUAL(keys.size(), dq.ids.qname.countLabels());
    BOOST_REQUIRE(!keys.empty());
    BOOST_CHECK_EQUAL(keys.at(0), dq.ids.qname.toDNSStringLC());
    std::string value;
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(0), value), true);
    BOOST_CHECK_EQUAL(value, "this is the value for the qname");
    value.clear();
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(1), value), false);

    /* other domain, should not match */
    keys = lookupKey->getKeys(notPDNS);
    BOOST_CHECK_EQUAL(keys.size(), notPDNS.countLabels());
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }

    /* subdomain, the second key should match */
    keys = lookupKey->getKeys(subdomain);
    BOOST_REQUIRE_EQUAL(keys.size(), subdomain.countLabels());
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(0), value), false);
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(1), value), true);
    BOOST_CHECK_EQUAL(value, "this is the value for the qname");

    /* this domain was inserted in plaintext, the wire format lookup should not match */
    keys = lookupKey->getKeys(plaintextDomain);
    BOOST_CHECK_EQUAL(keys.size(), plaintextDomain.countLabels());
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }
  }

  /* suffix match in plain text */
  {
    auto lookupKey = make_unique<KeyValueLookupKeySuffix>(0, false);
    auto keys = lookupKey->getKeys(dq);
    BOOST_CHECK_EQUAL(keys.size(), dq.ids.qname.countLabels());
    BOOST_REQUIRE(!keys.empty());
    BOOST_CHECK_EQUAL(keys.at(0), dq.ids.qname.toStringRootDot());
    std::string value;
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(0), value), false);
    value.clear();
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(1), value), false);

    /* other domain, should not match */
    keys = lookupKey->getKeys(notPDNS);
    BOOST_CHECK_EQUAL(keys.size(), notPDNS.countLabels());
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }

    /* subdomain, should not match in plain text */
    keys = lookupKey->getKeys(subdomain);
    BOOST_REQUIRE_EQUAL(keys.size(), subdomain.countLabels());
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), false);
    }

    /* this domain was inserted in plaintext, it should match */
    keys = lookupKey->getKeys(plaintextDomain);
    BOOST_REQUIRE_EQUAL(keys.size(), plaintextDomain.countLabels());
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(0), value), true);
    BOOST_CHECK_EQUAL(value, "this is the value for the plaintext domain");
  }

  /* suffix match in wire format, we require at least 2 labels */
  {
    auto lookupKey = make_unique<KeyValueLookupKeySuffix>(2, true);
    auto keys = lookupKey->getKeys(dq);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    BOOST_REQUIRE(!keys.empty());
    BOOST_CHECK_EQUAL(keys.at(0), dq.ids.qname.toDNSStringLC());
    std::string value;
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(0), value), true);
    BOOST_CHECK_EQUAL(value, "this is the value for the qname");
    value.clear();

    /* subdomain */
    keys = lookupKey->getKeys(subdomain);
    BOOST_REQUIRE_EQUAL(keys.size(), 2U);
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(0), value), false);
    BOOST_CHECK_EQUAL(kvs->getValue(keys.at(1), value), true);
    BOOST_CHECK_EQUAL(value, "this is the value for the qname");
  }
}

#if defined(HAVE_LMDB)
static void doKVSRangeChecks(std::unique_ptr<KeyValueStore>& kvs)
{
  {
    /* do a range-based lookup */
    const ComboAddress first("2001:0db8:0000:0000:0000:0000:0000:0000");
    const ComboAddress inside("2001:0db8:7fff:ffff:ffff:ffff:ffff:ffff");
    const ComboAddress last("2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff");
    const ComboAddress notInRange1("2001:0db7:ffff:ffff:ffff:ffff:ffff:ffff");
    const ComboAddress notInRange2("2001:0db9:0000:0000:0000:0000:0000:0000");
    const std::string expectedValue = std::string(reinterpret_cast<const char*>(&first.sin6.sin6_addr.s6_addr), sizeof(first.sin6.sin6_addr.s6_addr)) + std::string("any other data");

    auto check = [expectedValue, &kvs](const ComboAddress& key, bool shouldBeFound) {
      // cerr<<"Checking "<<key.toString()<<", should "<<(shouldBeFound ? "" : "NOT ")<<"be found"<<endl;
      auto lookupKey = std::string(reinterpret_cast<const char*>(&key.sin6.sin6_addr.s6_addr), sizeof(key.sin6.sin6_addr.s6_addr));
      std::string value;
      BOOST_CHECK_EQUAL(kvs->getRangeValue(lookupKey, value), shouldBeFound);
      if (shouldBeFound) {
        BOOST_CHECK_EQUAL(value, expectedValue);
      }
    };

    check(first, true);
    check(last, true);
    check(inside, true);
    check(notInRange1, false);
    check(notInRange2, false);
  }

  {
    const ComboAddress first("192.0.2.1:0");
    const ComboAddress inside("192.0.2.1:42");
    const ComboAddress last("192.0.2.1:16383");
    const ComboAddress notInRange1("192.0.2.0:65535");
    const ComboAddress notInRange2("192.0.2.1:16384");
    const std::string expectedValue = std::string(reinterpret_cast<const char*>(&first.sin4.sin_addr.s_addr), sizeof(first.sin4.sin_addr.s_addr)) + std::string(reinterpret_cast<const char*>(&first.sin4.sin_port), sizeof(first.sin4.sin_port)) + std::string("any other data");

    auto check = [expectedValue, &kvs](const ComboAddress& key, bool shouldBeFound) {
      // cerr<<"Checking "<<key.toStringWithPort()<<", should "<<(shouldBeFound ? "" : "NOT ")<<"be found"<<endl;
      auto lookupKey = std::string(reinterpret_cast<const char*>(&key.sin4.sin_addr.s_addr), sizeof(key.sin4.sin_addr.s_addr)) + std::string(reinterpret_cast<const char*>(&key.sin4.sin_port), sizeof(key.sin4.sin_port));
      std::string value;
      BOOST_CHECK_EQUAL(kvs->getRangeValue(lookupKey, value), shouldBeFound);
      if (shouldBeFound) {
        BOOST_CHECK_EQUAL(value, expectedValue);
      }
    };

    check(first, true);
    check(last, true);
    check(inside, true);
    check(notInRange1, false);
    check(notInRange2, false);
  }
}
#endif // defined(HAVE_LMDB)

#endif // defined(HAVE_LMDB) || defined(HAVE_CDB)

BOOST_AUTO_TEST_SUITE(dnsdistkvs_cc)

#ifdef HAVE_LMDB
BOOST_AUTO_TEST_CASE(test_LMDB)
{

  InternalQueryState ids;
  ids.qname = DNSName("powerdns.com.");
  DNSName plaintextDomain("powerdns.org.");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.origDest = ComboAddress("192.0.2.1:53");
  ids.origRemote = ComboAddress("192.0.2.128:42");
  PacketBuffer packet(sizeof(dnsheader));
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.queryRealTime.start();
  struct timespec expiredTime;
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  DNSQuestion dq(ids, packet);
  ComboAddress v4Masked(v4ToMask);
  ComboAddress v6Masked(v6ToMask);
  v4Masked.truncate(25);
  v6Masked.truncate(65);

  const ComboAddress firstRangeAddr6("2001:0db8:0000:0000:0000:0000:0000:0000");
  const ComboAddress lastRangeAddr6("2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff");
  const ComboAddress firstRangeAddr4("192.0.2.1:0");
  const ComboAddress lastRangeAddr4("192.0.2.1:16383");

  string dbPath("/tmp/test_lmdb.XXXXXX");
  {
    MDBEnv env(dbPath.c_str(), MDB_NOSUBDIR, 0600, 50);
    auto transaction = env.getRWTransaction();
    auto dbi = transaction->openDB("db-name", MDB_CREATE);
    transaction->put(dbi, MDBInVal(std::string(reinterpret_cast<const char*>(&ids.origRemote.sin4.sin_addr.s_addr), sizeof(ids.origRemote.sin4.sin_addr.s_addr))), MDBInVal("this is the value for the remote addr"));
    transaction->put(dbi, MDBInVal(std::string(reinterpret_cast<const char*>(&ids.origRemote.sin4.sin_addr.s_addr), sizeof(ids.origRemote.sin4.sin_addr.s_addr)) + std::string(reinterpret_cast<const char*>(&ids.origRemote.sin4.sin_port), sizeof(ids.origRemote.sin4.sin_port))), MDBInVal("this is the value for the remote addr + port"));
    transaction->put(dbi, MDBInVal(std::string(reinterpret_cast<const char*>(&v4Masked.sin4.sin_addr.s_addr), sizeof(v4Masked.sin4.sin_addr.s_addr))), MDBInVal("this is the value for the masked v4 addr"));
    transaction->put(dbi, MDBInVal(std::string(reinterpret_cast<const char*>(&v6Masked.sin6.sin6_addr.s6_addr), sizeof(v6Masked.sin6.sin6_addr.s6_addr))), MDBInVal("this is the value for the masked v6 addr"));
    transaction->put(dbi, MDBInVal(dq.ids.qname.toDNSStringLC()), MDBInVal("this is the value for the qname"));
    transaction->put(dbi, MDBInVal(plaintextDomain.toStringRootDot()), MDBInVal("this is the value for the plaintext domain"));

    transaction->commit();
  }

  {
    MDBEnv env(dbPath.c_str(), MDB_NOSUBDIR, 0600, 50);
    auto transaction = env.getRWTransaction();
    auto dbi = transaction->openDB("range-db-name", MDB_CREATE);
    /* range-based lookups */
    std::string value = std::string(reinterpret_cast<const char*>(&firstRangeAddr6.sin6.sin6_addr.s6_addr), sizeof(firstRangeAddr6.sin6.sin6_addr.s6_addr)) + std::string("any other data");
    transaction->put(dbi, MDBInVal(std::string(reinterpret_cast<const char*>(&lastRangeAddr6.sin6.sin6_addr.s6_addr), sizeof(lastRangeAddr6.sin6.sin6_addr.s6_addr))), MDBInVal(value));

    value = std::string(reinterpret_cast<const char*>(&firstRangeAddr4.sin4.sin_addr.s_addr), sizeof(firstRangeAddr4.sin4.sin_addr.s_addr)) + std::string(reinterpret_cast<const char*>(&firstRangeAddr4.sin4.sin_port), sizeof(firstRangeAddr4.sin4.sin_port)) + std::string("any other data");
    transaction->put(dbi, MDBInVal(std::string(reinterpret_cast<const char*>(&lastRangeAddr4.sin4.sin_addr.s_addr), sizeof(lastRangeAddr4.sin4.sin_addr.s_addr)) + std::string(reinterpret_cast<const char*>(&lastRangeAddr4.sin4.sin_port), sizeof(lastRangeAddr4.sin4.sin_port))), MDBInVal(value));

    transaction->commit();
  }

  std::unique_ptr<KeyValueStore> lmdb = std::make_unique<LMDBKVStore>(dbPath, "db-name");
  doKVSChecks(lmdb, ids.origDest, ids.origRemote, dq, plaintextDomain);
  lmdb.reset();

  lmdb = std::make_unique<LMDBKVStore>(dbPath, "range-db-name");
  doKVSRangeChecks(lmdb);

  unlink(dbPath.c_str());
  dbPath += "-lock";
  unlink(dbPath.c_str());

  /*
  std::string value;
  DTime dt;
  dt.set();
  for (size_t idx = 0; idx < 10000000; idx++) {
    auto keys = lookupKey->getKeys(dq);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(lmdb->getValue(key, value), true);
      BOOST_CHECK_EQUAL(value, "this is the value of the tag");
    }
  }
  cerr<<dt.udiff()/1000/1000<<endl;
  */
}
#endif /* HAVE_LMDB */

#ifdef HAVE_CDB
BOOST_AUTO_TEST_CASE(test_CDB)
{

  InternalQueryState ids;
  ids.qname = DNSName("powerdns.com.");
  DNSName plaintextDomain("powerdns.org.");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.origDest = ComboAddress("192.0.2.1:53");
  ids.origRemote = ComboAddress("192.0.2.128:42");
  PacketBuffer packet(sizeof(dnsheader));
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.queryRealTime.start();
  struct timespec expiredTime;
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  DNSQuestion dq(ids, packet);
  ComboAddress v4Masked(v4ToMask);
  ComboAddress v6Masked(v6ToMask);
  v4Masked.truncate(25);
  v6Masked.truncate(65);

  char db[] = "/tmp/test_cdb.XXXXXX";
  {
    int fd = mkstemp(db);
    BOOST_REQUIRE(fd >= 0);
    CDBWriter writer(fd);
    BOOST_REQUIRE(writer.addEntry(std::string(reinterpret_cast<const char*>(&ids.origRemote.sin4.sin_addr.s_addr), sizeof(ids.origRemote.sin4.sin_addr.s_addr)), "this is the value for the remote addr"));
    BOOST_REQUIRE(writer.addEntry(std::string(reinterpret_cast<const char*>(&ids.origRemote.sin4.sin_addr.s_addr), sizeof(ids.origRemote.sin4.sin_addr.s_addr)) + std::string(reinterpret_cast<const char*>(&ids.origRemote.sin4.sin_port), sizeof(ids.origRemote.sin4.sin_port)), "this is the value for the remote addr + port"));
    BOOST_REQUIRE(writer.addEntry(std::string(reinterpret_cast<const char*>(&v4Masked.sin4.sin_addr.s_addr), sizeof(v4Masked.sin4.sin_addr.s_addr)), "this is the value for the masked v4 addr"));
    BOOST_REQUIRE(writer.addEntry(std::string(reinterpret_cast<const char*>(&v6Masked.sin6.sin6_addr.s6_addr), sizeof(v6Masked.sin6.sin6_addr.s6_addr)), "this is the value for the masked v6 addr"));
    BOOST_REQUIRE(writer.addEntry(dq.ids.qname.toDNSStringLC(), "this is the value for the qname"));
    BOOST_REQUIRE(writer.addEntry(plaintextDomain.toStringRootDot(), "this is the value for the plaintext domain"));
    writer.close();
  }

  std::unique_ptr<KeyValueStore> cdb = std::make_unique<CDBKVStore>(db, 0);
  doKVSChecks(cdb, ids.origDest, ids.origRemote, dq, plaintextDomain);

  unlink(db);

  /*
  std::string value;
  DTime dt;
  dt.set();
  auto lookupKey = make_unique<KeyValueLookupKeySourceIP>();
  for (size_t idx = 0; idx < 100000000; idx++) {
    auto keys = lookupKey->getKeys(dq);
    for (const auto& key : keys) {
      if (!cdb->getValue(key, value)) {
        cerr<<"key not found"<<endl;
        break;
      }
      if (value != "this is the value for the remote addr") {
        cerr<<"invalid value found"<<endl;
        break;
      }
    }
  }
  cerr<<dt.udiff()/1000/1000<<endl;
  */
}
#endif /* HAVE_CDB */

BOOST_AUTO_TEST_SUITE_END()
