#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>

#include "negcache.hh"
#include "dnsrecords.hh"
#include "utility.hh"

static recordsAndSignatures genRecsAndSigs(const DNSName& name, const uint16_t qtype, const string& content, bool sigs)
{
  recordsAndSignatures ret;

  DNSRecord rec;
  rec.d_name = name;
  rec.d_type = qtype;
  rec.d_ttl = 600;
  rec.d_place = DNSResourceRecord::AUTHORITY;
  rec.setContent(DNSRecordContent::make(qtype, QClass::IN, content));

  ret.records.push_back(rec);

  if (sigs) {
    rec.d_type = QType::RRSIG;
    rec.setContent(std::make_shared<RRSIGRecordContent>(QType(qtype).toString() + " 5 3 600 2037010100000000 2037010100000000 24567 dummy data"));
    ret.signatures.push_back(rec);
  }

  return ret;
}

static NegCache::NegCacheEntry genNegCacheEntry(const DNSName& name, const DNSName& auth, const struct timeval& now, const uint16_t qtype = 0)
{
  NegCache::NegCacheEntry ret;

  ret.d_name = name;
  ret.d_qtype = QType(qtype);
  ret.d_auth = auth;
  ret.d_ttd = now.tv_sec + 600;
  ret.d_orig_ttl = 600;
  ret.authoritySOA = genRecsAndSigs(auth, QType::SOA, "ns1 hostmaster 1 2 3 4 5", true);
  ret.DNSSECRecords = genRecsAndSigs(auth, QType::NSEC, "deadbeef", true);

  return ret;
}

BOOST_AUTO_TEST_SUITE(negcache_cc)

BOOST_AUTO_TEST_CASE(test_get_entry)
{
  /* Add a full name negative entry to the cache and attempt to get an entry for
   * the A record. Should yield the full name does not exist entry
   */
  DNSName qname("www2.powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));

  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry ne;
  bool ret = cache.get(qname, QType(1), now, ne);

  BOOST_CHECK(ret);
  BOOST_CHECK_EQUAL(ne.d_name, qname);
  BOOST_CHECK_EQUAL(ne.d_qtype.toString(), QType(0).toString());
  BOOST_CHECK_EQUAL(ne.d_auth, auth);
}

BOOST_AUTO_TEST_CASE(test_get_entry2038)
{
  /* Add a full name negative entry to the cache and attempt to get an entry for
   * the A record. Should yield the full name does not exist entry
   */
  DNSName qname("www2.powerdns.com");
  DNSName auth("powerdns.com");

  timeval now{INT_MAX - 300, 0};

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));

  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry ne;
  bool ret = cache.get(qname, QType(QType::A), now, ne);

  BOOST_CHECK(ret);
  BOOST_CHECK_EQUAL(ne.d_name, qname);
  BOOST_CHECK_EQUAL(ne.d_qtype.toString(), QType(0).toString());
  BOOST_CHECK_EQUAL(ne.d_auth, auth);
}

BOOST_AUTO_TEST_CASE(test_get_entry_exact_type)
{
  /* Add a full name negative entry to the cache and attempt to get an entry for
   * the A record, asking only for an exact match.
   */
  DNSName qname("www2.powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));

  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry ne;
  bool ret = cache.get(qname, QType(1), now, ne, true);

  BOOST_CHECK_EQUAL(ret, false);
}

BOOST_AUTO_TEST_CASE(test_get_NODATA_entry)
{
  DNSName qname("www2.powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now, 1));

  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry ne;
  bool ret = cache.get(qname, QType(1), now, ne);

  BOOST_CHECK(ret);
  BOOST_CHECK_EQUAL(ne.d_name, qname);
  BOOST_CHECK_EQUAL(ne.d_qtype.toString(), QType(1).toString());
  BOOST_CHECK_EQUAL(ne.d_auth, auth);

  NegCache::NegCacheEntry ne2;
  ret = cache.get(qname, QType(16), now, ne2);
  BOOST_CHECK_EQUAL(ret, false);
}

BOOST_AUTO_TEST_CASE(test_getRootNXTrust_entry)
{
  DNSName qname("com");
  DNSName auth(".");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));

  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry ne;
  bool ret = cache.getRootNXTrust(qname, now, ne, false, false);

  BOOST_CHECK(ret);
  BOOST_CHECK_EQUAL(ne.d_name, qname);
  BOOST_CHECK_EQUAL(ne.d_qtype.toString(), QType(0).toString());
  BOOST_CHECK_EQUAL(ne.d_auth, auth);
}

BOOST_AUTO_TEST_CASE(test_add_and_get_expired_entry)
{
  DNSName qname("www2.powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);
  now.tv_sec -= 1000;

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));

  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry ne;

  now.tv_sec += 1000;
  bool ret = cache.get(qname, QType(1), now, ne);

  BOOST_CHECK_EQUAL(ret, false);
}

BOOST_AUTO_TEST_CASE(test_getRootNXTrust_expired_entry)
{
  DNSName qname("com");
  DNSName auth(".");

  struct timeval now;
  Utility::gettimeofday(&now, 0);
  now.tv_sec -= 1000;

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));

  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry ne;

  now.tv_sec += 1000;
  bool ret = cache.getRootNXTrust(qname, now, ne, false, false);

  BOOST_CHECK_EQUAL(ret, false);
}

BOOST_AUTO_TEST_CASE(test_add_updated_entry)
{
  DNSName qname("www2.powerdns.com");
  DNSName auth("powerdns.com");
  DNSName auth2("com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));
  // Should override the existing entry for www2.powerdns.com
  cache.add(genNegCacheEntry(qname, auth2, now));

  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry ne;
  bool ret = cache.get(qname, QType(1), now, ne);

  BOOST_CHECK(ret);
  BOOST_CHECK_EQUAL(ne.d_name, qname);
  BOOST_CHECK_EQUAL(ne.d_auth, auth2);
}

BOOST_AUTO_TEST_CASE(test_getRootNXTrust)
{
  DNSName qname("www2.powerdns.com");
  DNSName auth("powerdns.com");
  DNSName qname2("com");
  DNSName auth2(".");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));
  cache.add(genNegCacheEntry(qname2, auth2, now));

  NegCache::NegCacheEntry ne;
  bool ret = cache.getRootNXTrust(qname, now, ne, false, false);

  BOOST_CHECK(ret);
  BOOST_CHECK_EQUAL(ne.d_name, qname2);
  BOOST_CHECK_EQUAL(ne.d_auth, auth2);
}

BOOST_AUTO_TEST_CASE(test_getRootNXTrust_full_domain_only)
{
  DNSName qname("www2.powerdns.com");
  DNSName auth("powerdns.com");
  DNSName qname2("com");
  DNSName auth2(".");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  cache.add(genNegCacheEntry(qname, auth, now));
  cache.add(genNegCacheEntry(qname2, auth2, now, 1)); // Add the denial for COM|A

  NegCache::NegCacheEntry ne;
  bool ret = cache.getRootNXTrust(qname, now, ne, false, false);

  BOOST_CHECK_EQUAL(ret, false);
}

BOOST_AUTO_TEST_CASE(test_prune)
{
  string qname(".powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache(1);
  NegCache::NegCacheEntry ne;
  for (int i = 0; i < 400; i++) {
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname), auth, now);
    cache.add(ne);
  }

  BOOST_CHECK_EQUAL(cache.size(), 400U);

  cache.prune(now.tv_sec, 100);

  BOOST_CHECK_EQUAL(cache.size(), 100U);
}

BOOST_AUTO_TEST_CASE(test_prune_many_shards)
{
  string qname(".powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  NegCache::NegCacheEntry ne;
  for (int i = 0; i < 400; i++) {
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname), auth, now);
    cache.add(ne);
  }

  BOOST_CHECK_EQUAL(cache.size(), 400U);

  cache.prune(now.tv_sec, 100);

  BOOST_CHECK_EQUAL(cache.size(), 100U);
}

BOOST_AUTO_TEST_CASE(test_prune_valid_entries)
{
  DNSName power1("powerdns.com.");
  DNSName power2("powerdns-1.com.");
  DNSName auth("com.");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  NegCache::NegCacheEntry ne;

  /* insert power1 then power2 */
  ne = genNegCacheEntry(power1, auth, now);
  cache.add(ne);
  ne = genNegCacheEntry(power2, auth, now);
  cache.add(ne);

  BOOST_CHECK_EQUAL(cache.size(), 2U);

  /* power2 has been inserted more recently, so it should be
     removed last */
  cache.prune(now.tv_sec, 1);
  BOOST_CHECK_EQUAL(cache.size(), 1U);

  NegCache::NegCacheEntry got;
  bool ret = cache.get(power2, QType(1), now, got);
  BOOST_REQUIRE(ret);
  BOOST_CHECK_EQUAL(got.d_name, power2);
  BOOST_CHECK_EQUAL(got.d_auth, auth);

  /* insert power1 back */
  ne = genNegCacheEntry(power1, auth, now);
  cache.add(ne);
  BOOST_CHECK_EQUAL(cache.size(), 2U);

  /* replace the entry for power2 */
  ne = genNegCacheEntry(power2, auth, now);
  cache.add(ne);

  BOOST_CHECK_EQUAL(cache.size(), 2U);

  /* power2 has been updated more recently, so it should be
     removed last */
  cache.prune(now.tv_sec, 1);

  BOOST_CHECK_EQUAL(cache.size(), 1U);
  got = NegCache::NegCacheEntry();
  ret = cache.get(power2, QType(1), now, got);
  BOOST_REQUIRE(ret);
  BOOST_CHECK_EQUAL(got.d_name, power2);
  BOOST_CHECK_EQUAL(got.d_auth, auth);
}

BOOST_AUTO_TEST_CASE(test_wipe_single)
{
  string qname(".powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  NegCache::NegCacheEntry ne;
  ne = genNegCacheEntry(auth, auth, now);
  cache.add(ne);

  for (int i = 0; i < 400; i++) {
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname), auth, now);
    cache.add(ne);
  }

  BOOST_CHECK_EQUAL(cache.size(), 401U);

  // Should only wipe the powerdns.com entry
  cache.wipe(auth);
  BOOST_CHECK_EQUAL(cache.size(), 400U);

  NegCache::NegCacheEntry ne2;
  bool ret = cache.get(auth, QType(1), now, ne2);

  BOOST_CHECK_EQUAL(ret, false);

  cache.wipe(DNSName("1.powerdns.com"));
  BOOST_CHECK_EQUAL(cache.size(), 399U);

  NegCache::NegCacheEntry ne3;
  ret = cache.get(auth, QType(1), now, ne3);

  BOOST_CHECK_EQUAL(ret, false);
}

BOOST_AUTO_TEST_CASE(test_wipe_subtree)
{
  string qname(".powerdns.com");
  string qname2("powerdns.org");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  NegCache::NegCacheEntry ne;
  ne = genNegCacheEntry(auth, auth, now);
  cache.add(ne);

  for (int i = 0; i < 400; i++) {
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname), auth, now);
    cache.add(ne);
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname2), auth, now);
    cache.add(ne);
  }

  BOOST_CHECK_EQUAL(cache.size(), 801U);

  // Should wipe all the *.powerdns.com and powerdns.com entries
  cache.wipe(auth, true);
  BOOST_CHECK_EQUAL(cache.size(), 400U);
}

BOOST_AUTO_TEST_CASE(test_wipe_typed)
{
  string qname(".powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  NegCache::NegCacheEntry ne;
  ne = genNegCacheEntry(auth, auth, now, QType::A);
  cache.add(ne);

  for (int i = 0; i < 400; i++) {
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname), auth, now, QType::A);
    cache.add(ne);
  }

  BOOST_CHECK_EQUAL(cache.size(), 401U);

  // Should only wipe the powerdns.com entry
  cache.wipeTyped(auth, QType::A);
  BOOST_CHECK_EQUAL(cache.size(), 400U);

  NegCache::NegCacheEntry ne2;
  bool ret = cache.get(auth, QType(1), now, ne2);

  BOOST_CHECK_EQUAL(ret, false);

  cache.wipeTyped(DNSName("1.powerdns.com"), QType::A);
  BOOST_CHECK_EQUAL(cache.size(), 399U);

  NegCache::NegCacheEntry ne3;
  ret = cache.get(auth, QType(1), now, ne3);

  BOOST_CHECK_EQUAL(ret, false);
}

BOOST_AUTO_TEST_CASE(test_clear)
{
  string qname(".powerdns.com");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  NegCache::NegCacheEntry ne;

  for (int i = 0; i < 400; i++) {
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname), auth, now);
    cache.add(ne);
  }

  BOOST_CHECK_EQUAL(cache.size(), 400U);
  cache.clear();
  BOOST_CHECK_EQUAL(cache.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_dumpToFile)
{
  NegCache cache(1);
  vector<string> expected = {
    "; negcache dump follows\n",
    ";\n",
    "; negcache shard 0; size 2\n",
    "www1.powerdns.com. 600 IN TYPE0 VIA powerdns.com. ; (Indeterminate) origttl=600 ss=0\n",
    "powerdns.com. 600 IN SOA ns1. hostmaster. 1 2 3 4 5 ; (Indeterminate)\n",
    "powerdns.com. 600 IN RRSIG SOA 5 3 600 20370101000000 20370101000000 24567 dummy. data ;\n",
    "powerdns.com. 600 IN NSEC deadbeef. ; (Indeterminate)\n",
    "powerdns.com. 600 IN RRSIG NSEC 5 3 600 20370101000000 20370101000000 24567 dummy. data ;\n",
    "www2.powerdns.com. 600 IN TYPE0 VIA powerdns.com. ; (Indeterminate) origttl=600 ss=0\n",
    "powerdns.com. 600 IN SOA ns1. hostmaster. 1 2 3 4 5 ; (Indeterminate)\n",
    "powerdns.com. 600 IN RRSIG SOA 5 3 600 20370101000000 20370101000000 24567 dummy. data ;\n",
    "powerdns.com. 600 IN NSEC deadbeef. ; (Indeterminate)\n",
    "powerdns.com. 600 IN RRSIG NSEC 5 3 600 20370101000000 20370101000000 24567 dummy. data ;\n",
    "; negcache size: 2/0 shards: 1 min/max shard size: 2/2\n"};

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  cache.add(genNegCacheEntry(DNSName("www1.powerdns.com"), DNSName("powerdns.com"), now));
  cache.add(genNegCacheEntry(DNSName("www2.powerdns.com"), DNSName("powerdns.com"), now));

  auto filePtr = pdns::UniqueFilePtr(tmpfile());
  if (!filePtr) {
    BOOST_FAIL("Temporary file could not be opened");
  }

  cache.doDump(fileno(filePtr.get()), 0, now.tv_sec);

  rewind(filePtr.get());
  char* line = nullptr;
  size_t len = 0;
  ssize_t read;

  for (auto str : expected) {
    read = getline(&line, &len, filePtr.get());
    if (read == -1)
      BOOST_FAIL("Unable to read a line from the temp file");
    // The clock might have ticked so the 600 becomes 599
    BOOST_CHECK_EQUAL(line, str);
  }

  /* getline() allocates a buffer when called with a nullptr,
     then reallocates it when needed, but we need to free the
     last allocation if any. */
  free(line);
}

BOOST_AUTO_TEST_CASE(test_count)
{
  string qname(".powerdns.com");
  string qname2("powerdns.org");
  DNSName auth("powerdns.com");

  struct timeval now;
  Utility::gettimeofday(&now, 0);

  NegCache cache;
  NegCache::NegCacheEntry ne;
  ne = genNegCacheEntry(auth, auth, now);
  cache.add(ne);

  for (int i = 0; i < 400; i++) {
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname), auth, now);
    cache.add(ne);
    ne = genNegCacheEntry(DNSName(std::to_string(i) + qname2), auth, now);
    cache.add(ne);
  }

  uint64_t count;
  count = cache.count(auth);
  BOOST_CHECK_EQUAL(count, 1U);
  count = cache.count(auth, QType(1));
  BOOST_CHECK_EQUAL(count, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
