
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist-kvs.hh"

static void doKVSChecks(std::unique_ptr<KeyValueStore>& kvs, const ComboAddress& lc, const ComboAddress& rem, const DNSQuestion& dq, const DNSName& plaintextDomain)
{
  /* source IP */
  {
    auto lookupKey = make_unique<KeyValueLookupKeySourceIP>();
    std::string value;
    /* local address is not in the db, remote is */
    BOOST_CHECK_EQUAL(kvs->getValue(std::string(reinterpret_cast<const char*>(&lc.sin4.sin_addr.s_addr), sizeof(lc.sin4.sin_addr.s_addr)), value), false);
    BOOST_CHECK_EQUAL(kvs->keyExists(std::string(reinterpret_cast<const char*>(&lc.sin4.sin_addr.s_addr), sizeof(lc.sin4.sin_addr.s_addr))), false);
    BOOST_CHECK(kvs->keyExists(std::string(reinterpret_cast<const char*>(&dq.remote->sin4.sin_addr.s_addr), sizeof(dq.remote->sin4.sin_addr.s_addr))));

    auto keys = lookupKey->getKeys(dq);
    BOOST_CHECK_EQUAL(keys.size(), 1U);
    for (const auto& key : keys) {
      value.clear();
      BOOST_CHECK_EQUAL(kvs->getValue(key, value), true);
      BOOST_CHECK_EQUAL(value, "this is the value for the remote addr");
    }
  }

  const DNSName subdomain = DNSName("sub") + *dq.qname;
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
    BOOST_CHECK_EQUAL(keys.size(), dq.qname->countLabels());
    BOOST_REQUIRE(!keys.empty());
    BOOST_CHECK_EQUAL(keys.at(0), dq.qname->toDNSStringLC());
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
    BOOST_CHECK_EQUAL(keys.size(), dq.qname->countLabels());
    BOOST_REQUIRE(!keys.empty());
    BOOST_CHECK_EQUAL(keys.at(0), dq.qname->toStringRootDot());
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
    BOOST_CHECK_EQUAL(keys.at(0), dq.qname->toDNSStringLC());
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

BOOST_AUTO_TEST_SUITE(dnsdistkvs_cc)

#ifdef HAVE_LMDB
BOOST_AUTO_TEST_CASE(test_LMDB) {

  DNSName qname("powerdns.com.");
  DNSName plaintextDomain("powerdns.org.");
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  ComboAddress lc("192.0.2.1:53");
  ComboAddress rem("192.0.2.128:42");
  struct dnsheader dh;
  memset(&dh, 0, sizeof(dh));
  size_t bufferSize = 0;
  size_t queryLen = 0;
  bool isTcp = false;
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);
  struct timespec expiredTime;
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  DNSQuestion dq(&qname, qtype, qclass, qname.wirelength(), &lc, &rem, &dh, bufferSize, queryLen, isTcp, &queryRealTime);

  const string dbPath("/tmp/test_lmdb.XXXXXX");
  {
    MDBEnv env(dbPath.c_str(), MDB_NOSUBDIR, 0600);
    auto transaction = env.getRWTransaction();
    auto dbi = transaction.openDB("db-name", MDB_CREATE);
    transaction.put(dbi, MDBInVal(std::string(reinterpret_cast<const char*>(&rem.sin4.sin_addr.s_addr), sizeof(rem.sin4.sin_addr.s_addr))), MDBInVal("this is the value for the remote addr"));
    transaction.put(dbi, MDBInVal(qname.toDNSStringLC()), MDBInVal("this is the value for the qname"));
    transaction.put(dbi, MDBInVal(plaintextDomain.toStringRootDot()), MDBInVal("this is the value for the plaintext domain"));
    transaction.commit();
  }

  auto lmdb = std::unique_ptr<KeyValueStore>(new LMDBKVStore(dbPath, "db-name"));
  doKVSChecks(lmdb, lc, rem, dq, plaintextDomain);
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
BOOST_AUTO_TEST_CASE(test_CDB) {

  DNSName qname("powerdns.com.");
  DNSName plaintextDomain("powerdns.org.");
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  ComboAddress lc("192.0.2.1:53");
  ComboAddress rem("192.0.2.128:42");
  struct dnsheader dh;
  memset(&dh, 0, sizeof(dh));
  size_t bufferSize = 0;
  size_t queryLen = 0;
  bool isTcp = false;
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);
  struct timespec expiredTime;
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  DNSQuestion dq(&qname, qtype, qclass, qname.wirelength(), &lc, &rem, &dh, bufferSize, queryLen, isTcp, &queryRealTime);

  char db[] = "/tmp/test_cdb.XXXXXX";
  {
    int fd = mkstemp(db);
    BOOST_REQUIRE(fd >= 0);
    CDBWriter writer(fd);
    BOOST_REQUIRE(writer.addEntry(std::string(reinterpret_cast<const char*>(&rem.sin4.sin_addr.s_addr), sizeof(rem.sin4.sin_addr.s_addr)), "this is the value for the remote addr"));
    BOOST_REQUIRE(writer.addEntry(qname.toDNSStringLC(), "this is the value for the qname"));
    BOOST_REQUIRE(writer.addEntry(plaintextDomain.toStringRootDot(), "this is the value for the plaintext domain"));
    writer.close();
  }

  auto cdb = std::unique_ptr<KeyValueStore>(new CDBKVStore(db, 0));
  doKVSChecks(cdb, lc, rem, dq, plaintextDomain);

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
