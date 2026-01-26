
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <thread>
#include <boost/test/unit_test.hpp>

#include "dnsdist-rings.hh"
#include "gettime.hh"

BOOST_AUTO_TEST_SUITE(dnsdistrings_cc)

template <class T>
static bool checkQuery(const T& entry, const DNSName& qname, uint16_t qtype, uint16_t size, const timespec& now, const ComboAddress& requestor)
{
  if (entry.name != qname) {
    return false;
  }
  if (entry.qtype != qtype) {
    return false;
  }
  if (entry.size != size) {
    return false;
  }
  if (entry.when.tv_sec != now.tv_sec) {
    return false;
  }
  if (entry.requestor != requestor) {
    return false;
  }
  return true;
}

static bool checkResponse(const Rings::Response& entry, const DNSName& qname, uint16_t qtype, uint16_t size, const timespec& now, const ComboAddress& requestor, unsigned int latency, const ComboAddress& server)
{
  if (!checkQuery(entry, qname, qtype, size, now, requestor)) {
    return false;
  }
  if (entry.usec != latency) {
    return false;
  }
  if (entry.ds != server) {
    return false;
  }
  return true;
}

static void test_ring(size_t maxEntries, size_t numberOfShards, size_t nbLockTries)
{
  Rings rings;
  Rings::RingsConfiguration config{
    .capacity = maxEntries,
    .numberOfShards = numberOfShards,
    .nbLockTries = nbLockTries,
  };
  rings.init(config);
  size_t entriesPerShard = maxEntries / numberOfShards;

  BOOST_CHECK_EQUAL(rings.getNumberOfShards(), numberOfShards);
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), 0U);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), 0U);
  BOOST_CHECK_EQUAL(rings.d_shards.size(), rings.getNumberOfShards());
  for (const auto& shard : rings.d_shards) {
    BOOST_CHECK(shard != nullptr);
  }

  dnsheader dh;
  memset(&dh, 0, sizeof(dh));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  struct timespec now;
  gettime(&now);

  /* fill the query ring */
  for (size_t idx = 0; idx < maxEntries; idx++) {
    rings.insertQuery(now, requestor1, qname, qtype, size, dh, protocol);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), maxEntries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), 0U);
  for (const auto& shard : rings.d_shards) {
    auto ring = shard->queryRing.lock();
    BOOST_CHECK_EQUAL(ring->size(), entriesPerShard);
    for (const auto& entry : *ring) {
      BOOST_CHECK(checkQuery(entry, qname, qtype, size, now, requestor1));
    }
  }

  /* push enough queries to get rid of the existing ones */
  for (size_t idx = 0; idx < maxEntries; idx++) {
    rings.insertQuery(now, requestor2, qname, qtype, size, dh, protocol);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), maxEntries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), 0U);
  for (const auto& shard : rings.d_shards) {
    auto ring = shard->queryRing.lock();
    BOOST_CHECK_EQUAL(ring->size(), entriesPerShard);
    for (const auto& entry : *ring) {
      BOOST_CHECK(checkQuery(entry, qname, qtype, size, now, requestor2));
    }
  }

  ComboAddress server("192.0.2.42");
  unsigned int latency = 100;

  /* fill the response ring */
  for (size_t idx = 0; idx < maxEntries; idx++) {
    rings.insertResponse(now, requestor1, qname, qtype, latency, size, dh, server, outgoingProtocol);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), maxEntries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), maxEntries);
  for (const auto& shard : rings.d_shards) {
    auto ring = shard->respRing.lock();
    BOOST_CHECK_EQUAL(ring->size(), entriesPerShard);
    for (const auto& entry : *ring) {
      BOOST_CHECK(checkResponse(entry, qname, qtype, size, now, requestor1, latency, server));
    }
  }

  /* push enough responses to get rid of the existing ones */
  for (size_t idx = 0; idx < maxEntries; idx++) {
    rings.insertResponse(now, requestor2, qname, qtype, latency, size, dh, server, outgoingProtocol);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), maxEntries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), maxEntries);
  for (const auto& shard : rings.d_shards) {
    auto ring = shard->respRing.lock();
    BOOST_CHECK_EQUAL(ring->size(), entriesPerShard);
    for (const auto& entry : *ring) {
      BOOST_CHECK(checkResponse(entry, qname, qtype, size, now, requestor2, latency, server));
    }
  }
}

BOOST_AUTO_TEST_CASE(test_Rings_Simple)
{

  /* 5 entries over 1 shard */
  test_ring(5, 1, 0);
  /* 500 entries over 10 shards */
  test_ring(500, 10, 0);
  /* 5000 entries over 100 shards, max 5 try-lock attempts */
  test_ring(500, 100, 5);
}

static void ringReaderThread(Rings& rings, std::atomic<bool>& done, size_t numberOfEntries, uint16_t qtype)
{
  size_t iterationsDone = 0;

  while (done == false) {
    size_t numberOfQueries = 0;
    size_t numberOfResponses = 0;

    for (const auto& shard : rings.d_shards) {
      {
        auto rl = shard->queryRing.lock();
        for (const auto& c : *rl) {
          numberOfQueries++;
          // BOOST_CHECK* is slow as hell..
          if (c.qtype != qtype) {
            cerr << "Invalid query QType!" << endl;
            return;
          }
        }
      }
      {
        auto rl = shard->respRing.lock();
        for (const auto& c : *rl) {
          if (c.qtype != qtype) {
            cerr << "Invalid response QType!" << endl;
            return;
          }
          numberOfResponses++;
        }
      }
    }

    BOOST_CHECK_LE(numberOfQueries, numberOfEntries);
    BOOST_CHECK_LE(numberOfResponses, numberOfEntries);
    iterationsDone++;
    usleep(10000);
  }

  BOOST_CHECK_GT(iterationsDone, 1U);
#if 0
  cerr<<"Done "<<iterationsDone<<" reading iterations"<<endl;
#endif
}

static void ringWriterThread(Rings& rings, size_t numberOfEntries, const Rings::Query& query, const Rings::Response& response)
{
  for (size_t idx = 0; idx < numberOfEntries; idx++) {
    rings.insertQuery(query.when, query.requestor, query.name, query.qtype, query.size, query.dh, query.protocol);
    rings.insertResponse(response.when, response.requestor, response.name, response.qtype, response.usec, response.size, response.dh, response.ds, response.protocol);
  }
}

BOOST_AUTO_TEST_CASE(test_Rings_Threaded)
{
  size_t numberOfEntries = 1000000;
  size_t numberOfShards = 50;
  size_t lockAttempts = 5;
  size_t numberOfWriterThreads = 4;
  size_t entriesPerShard = numberOfEntries / numberOfShards;

  struct timespec now;
  gettime(&now);
  dnsheader dh;
  memset(&dh, 0, sizeof(dh));
  dh.id = htons(4242);
  dh.qr = 0;
  dh.tc = 0;
  dh.rd = 0;
  dh.rcode = 0;
  dh.qdcount = htons(1);
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor("192.0.2.1");
  ComboAddress server("192.0.2.42");
  unsigned int latency = 100;
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;

  Rings rings;
  Rings::RingsConfiguration config{
    .capacity = numberOfEntries,
    .numberOfShards = numberOfShards,
    .nbLockTries = lockAttempts,
  };
  rings.init(config);
#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
  Rings::Query query({requestor, qname, now, dh, size, qtype, protocol, dnsdist::MacAddress(), false});
#else
  Rings::Query query({requestor, qname, now, dh, size, qtype, protocol});
#endif
  Rings::Response response({requestor, server, qname, now, dh, latency, size, qtype, outgoingProtocol});

  std::atomic<bool> done(false);
  std::vector<std::thread> writerThreads;
  std::thread readerThread(ringReaderThread, std::ref(rings), std::ref(done), numberOfEntries, qtype);

  /* we need to overcommit a bit to account for the fact that due to contention,
     we might not perfectly distribute the entries over the shards,
     so some of them might get full while other still have some place left */
  size_t insertionsPerThread = (1.2 * numberOfEntries) / numberOfWriterThreads;
  for (size_t idx = 0; idx < numberOfWriterThreads; idx++) {
    writerThreads.push_back(std::thread(ringWriterThread, std::ref(rings), insertionsPerThread, query, response));
  }

  /* wait for the writers to be finished */
  for (auto& t : writerThreads) {
    t.join();
  }

  /* we can stop the reader thread now */
  done = true;
  readerThread.join();

  BOOST_CHECK_EQUAL(rings.getNumberOfShards(), numberOfShards);
  BOOST_CHECK_EQUAL(rings.d_shards.size(), rings.getNumberOfShards());
  BOOST_CHECK_LE(rings.getNumberOfQueryEntries(), numberOfEntries);
  BOOST_CHECK_GT(rings.getNumberOfQueryEntries(), numberOfEntries * 0.75);
  BOOST_WARN_GT(rings.getNumberOfQueryEntries(), numberOfEntries * 0.99);
  BOOST_CHECK_LE(rings.getNumberOfResponseEntries(), numberOfEntries);
  BOOST_CHECK_GT(rings.getNumberOfResponseEntries(), numberOfEntries * 0.75);
  BOOST_WARN_GT(rings.getNumberOfResponseEntries(), numberOfEntries * 0.99);

  size_t totalQueries = 0;
  size_t totalResponses = 0;
  for (const auto& shard : rings.d_shards) {
    {
      auto ring = shard->queryRing.lock();
      BOOST_CHECK_LE(ring->size(), entriesPerShard);
      // verify that the shard is not empty
      BOOST_CHECK_GT(ring->size(), (entriesPerShard * 0.5) + 1);
      // this would be optimal
      BOOST_WARN_GT(ring->size(), entriesPerShard * 0.95);
      totalQueries += ring->size();
      for (const auto& entry : *ring) {
        BOOST_CHECK(checkQuery(entry, qname, qtype, size, now, requestor));
      }
    }
    {
      auto ring = shard->respRing.lock();
      BOOST_CHECK_LE(ring->size(), entriesPerShard);
      // verify that the shard is not empty
      BOOST_CHECK_GT(ring->size(), (entriesPerShard * 0.5) + 1);
      // this would be optimal
      BOOST_WARN_GT(ring->size(), entriesPerShard * 0.95);
      totalResponses += ring->size();
      for (const auto& entry : *ring) {
        BOOST_CHECK(checkResponse(entry, qname, qtype, size, now, requestor, latency, server));
      }
    }
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), totalQueries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), totalResponses);
#if 0
  cerr<<"Done "<<(insertionsPerThread*numberOfWriterThreads)<<" insertions"<<endl;
  cerr<<"Got "<<rings.d_deferredQueryInserts<<" deferred query insertions"<<endl;
  cerr<<"Got "<<rings.d_blockingQueryInserts<<" blocking query insertions"<<endl;
  cerr<<"Got "<<rings.d_deferredResponseInserts<<" deferred response insertions"<<endl;
  cerr<<"Got "<<rings.d_blockingResponseInserts<<" blocking response insertions"<<endl;
#endif
}

BOOST_AUTO_TEST_CASE(test_Rings_Sampling)
{
  const size_t numberOfEntries = 10000;
  const size_t numberOfShards = 50;
  const size_t samplingRate = 10;

  Rings rings;
  const Rings::RingsConfiguration config{
    .capacity = numberOfEntries,
    .numberOfShards = numberOfShards,
    .samplingRate = samplingRate,
  };
  rings.init(config);

  BOOST_CHECK_EQUAL(rings.adjustForSamplingRate(0U), 0U);
  BOOST_CHECK_EQUAL(rings.adjustForSamplingRate(1U), 1U * samplingRate);

  timespec now{};
  gettime(&now);
  dnsheader dh{};
  dh.id = htons(4242);
  dh.qr = 0;
  dh.tc = 0;
  dh.rd = 0;
  dh.rcode = 0;
  dh.qdcount = htons(1);
  const DNSName qname("rings.powerdns.com.");
  const ComboAddress requestor("192.0.2.1");
  const ComboAddress server("192.0.2.42");
  const unsigned int latency = 100;
  const uint16_t qtype = QType::AAAA;
  const uint16_t size = 42;
  const dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  const dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;

  size_t numberOfQueries = 1000U;
  for (size_t idx = 0; idx < numberOfQueries; idx++) {
    rings.insertQuery(now, requestor, qname, qtype, size, dh, protocol);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), numberOfQueries / samplingRate);

  size_t numberOfResponses = 5000U;
  for (size_t idx = 0; idx < numberOfResponses; idx++) {
    rings.insertResponse(now, requestor, qname, qtype, latency, size, dh, server, outgoingProtocol);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), numberOfResponses / samplingRate);

  rings.clear();
  /* now we insert more queries and responses than the rings can hold, even taking the sampling rate into account,
     it should just discard the oldest ones */
  numberOfQueries = 2U * samplingRate * numberOfEntries;
  for (size_t idx = 0; idx < numberOfQueries; idx++) {
    rings.insertQuery(now, requestor, qname, qtype, size, dh, protocol);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), numberOfEntries);

  numberOfResponses = 2U * samplingRate * numberOfEntries;
  for (size_t idx = 0; idx < numberOfResponses; idx++) {
    rings.insertResponse(now, requestor, qname, qtype, latency, size, dh, server, outgoingProtocol);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), numberOfEntries);
}

BOOST_AUTO_TEST_SUITE_END()
