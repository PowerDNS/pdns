
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <thread>
#include <boost/test/unit_test.hpp>

#include "dnsdist-rings.hh"
#include "gettime.hh"

BOOST_AUTO_TEST_SUITE(dnsdistrings_cc)

static void test_ring(size_t maxEntries, size_t numberOfShards, size_t nbLockTries)
{
  Rings rings(maxEntries, numberOfShards, nbLockTries);
  size_t entriesPerShard = maxEntries / numberOfShards;

  BOOST_CHECK_EQUAL(rings.getNumberOfShards(), numberOfShards);
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), 0U);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), 0U);
  BOOST_CHECK_EQUAL(rings.d_shards.size(), rings.getNumberOfShards());
  for (const auto& shard : rings.d_shards) {
    BOOST_CHECK(shard != nullptr);
  }

  dnsheader dh;
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  struct timespec now;
  gettime(&now);

  /* fill the query ring */
  for (size_t idx = 0; idx < maxEntries; idx++) {
    rings.insertQuery(now, requestor1, qname, qtype, size, dh);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), maxEntries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), 0U);
  for (const auto& shard : rings.d_shards) {
    BOOST_CHECK_EQUAL(shard->queryRing.size(), entriesPerShard);
    for (const auto& entry : shard->queryRing) {
      BOOST_CHECK_EQUAL(entry.name, qname);
      BOOST_CHECK_EQUAL(entry.qtype, qtype);
      BOOST_CHECK_EQUAL(entry.size, size);
      BOOST_CHECK_EQUAL(entry.when.tv_sec, now.tv_sec);
      BOOST_CHECK_EQUAL(entry.requestor.toStringWithPort(), requestor1.toStringWithPort());
    }
  }

  /* push enough queries to get rid of the existing ones */
  for (size_t idx = 0; idx < maxEntries; idx++) {
    rings.insertQuery(now, requestor2, qname, qtype, size, dh);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), maxEntries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), 0U);
  for (const auto& shard : rings.d_shards) {
    BOOST_CHECK_EQUAL(shard->queryRing.size(), entriesPerShard);
    for (const auto& entry : shard->queryRing) {
      BOOST_CHECK_EQUAL(entry.name, qname);
      BOOST_CHECK_EQUAL(entry.qtype, qtype);
      BOOST_CHECK_EQUAL(entry.size, size);
      BOOST_CHECK_EQUAL(entry.when.tv_sec, now.tv_sec);
      BOOST_CHECK_EQUAL(entry.requestor.toStringWithPort(), requestor2.toStringWithPort());
    }
  }

  ComboAddress server("192.0.2.42");
  unsigned int latency = 100;

  /* fill the response ring */
  for (size_t idx = 0; idx < maxEntries; idx++) {
    rings.insertResponse(now, requestor1, qname, qtype, latency, size, dh, server);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), maxEntries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), maxEntries);
  for (const auto& shard : rings.d_shards) {
    BOOST_CHECK_EQUAL(shard->respRing.size(), entriesPerShard);
    for (const auto& entry : shard->respRing) {
      BOOST_CHECK_EQUAL(entry.name, qname);
      BOOST_CHECK_EQUAL(entry.qtype, qtype);
      BOOST_CHECK_EQUAL(entry.size, size);
      BOOST_CHECK_EQUAL(entry.when.tv_sec, now.tv_sec);
      BOOST_CHECK_EQUAL(entry.requestor.toStringWithPort(), requestor1.toStringWithPort());
      BOOST_CHECK_EQUAL(entry.usec, latency);
      BOOST_CHECK_EQUAL(entry.ds.toStringWithPort(), server.toStringWithPort());
    }
  }

  /* push enough responses to get rid of the existing ones */
  for (size_t idx = 0; idx < maxEntries; idx++) {
    rings.insertResponse(now, requestor2, qname, qtype, latency, size, dh, server);
  }
  BOOST_CHECK_EQUAL(rings.getNumberOfQueryEntries(), maxEntries);
  BOOST_CHECK_EQUAL(rings.getNumberOfResponseEntries(), maxEntries);
  for (const auto& shard : rings.d_shards) {
    BOOST_CHECK_EQUAL(shard->respRing.size(), entriesPerShard);
    for (const auto& entry : shard->respRing) {
      BOOST_CHECK_EQUAL(entry.name, qname);
      BOOST_CHECK_EQUAL(entry.qtype, qtype);
      BOOST_CHECK_EQUAL(entry.size, size);
      BOOST_CHECK_EQUAL(entry.when.tv_sec, now.tv_sec);
      BOOST_CHECK_EQUAL(entry.requestor.toStringWithPort(), requestor2.toStringWithPort());
      BOOST_CHECK_EQUAL(entry.usec, latency);
      BOOST_CHECK_EQUAL(entry.ds.toStringWithPort(), server.toStringWithPort());
    }
  }
}


BOOST_AUTO_TEST_CASE(test_Rings_Simple) {

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
        std::lock_guard<std::mutex> rl(shard->queryLock);
        for(const auto& c : shard->queryRing) {
          numberOfQueries++;
          // BOOST_CHECK* is slow as hell..
          if(c.qtype != qtype) {
            cerr<<"Invalid query QType!"<<endl;
            return;
          }
        }
      }
      {
        std::lock_guard<std::mutex> rl(shard->respLock);
        for(const auto& c : shard->respRing) {
          if(c.qtype != qtype) {
            cerr<<"Invalid response QType!"<<endl;
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

static void ringWriterThread(Rings& rings, size_t numberOfEntries, const Rings::Query query, const Rings::Response response)
{
  for (size_t idx = 0; idx < numberOfEntries; idx++) {
    rings.insertQuery(query.when, query.requestor, query.name, query.qtype, query.size, query.dh);
    rings.insertResponse(response.when, response.requestor, response.name, response.qtype, response.usec, response.size, response.dh, response.ds);
  }
}

BOOST_AUTO_TEST_CASE(test_Rings_Threaded) {
  size_t numberOfEntries = 1000000;
  size_t numberOfShards = 50;
  size_t lockAttempts = 5;
  size_t numberOfWriterThreads = 4;
  size_t entriesPerShard = numberOfEntries / numberOfShards;

  struct timespec now;
  gettime(&now);
  dnsheader dh;
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

  Rings rings(numberOfEntries, numberOfShards, lockAttempts, true);
  Rings::Query query({now, requestor, qname, size, qtype, dh});
  Rings::Response response({now, requestor, qname, qtype, latency, size, dh, server});

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
    BOOST_CHECK_LE(shard->queryRing.size(), entriesPerShard);
    // verify that the shard is not empty
    BOOST_CHECK_GT(shard->queryRing.size(), (entriesPerShard * 0.5) + 1);
    // this would be optimal
    BOOST_WARN_GT(shard->queryRing.size(), entriesPerShard * 0.95);
    totalQueries += shard->queryRing.size();
    for (const auto& entry : shard->queryRing) {
      BOOST_CHECK_EQUAL(entry.name, qname);
      BOOST_CHECK_EQUAL(entry.qtype, qtype);
      BOOST_CHECK_EQUAL(entry.size, size);
      BOOST_CHECK_EQUAL(entry.when.tv_sec, now.tv_sec);
      BOOST_CHECK_EQUAL(entry.requestor.toStringWithPort(), requestor.toStringWithPort());
    }
    BOOST_CHECK_LE(shard->respRing.size(), entriesPerShard);
    // verify that the shard is not empty
    BOOST_CHECK_GT(shard->queryRing.size(), (entriesPerShard * 0.5) + 1);
    // this would be optimal
    BOOST_WARN_GT(shard->respRing.size(), entriesPerShard * 0.95);
    totalResponses += shard->respRing.size();
    for (const auto& entry : shard->respRing) {
      BOOST_CHECK_EQUAL(entry.name, qname);
      BOOST_CHECK_EQUAL(entry.qtype, qtype);
      BOOST_CHECK_EQUAL(entry.size, size);
      BOOST_CHECK_EQUAL(entry.when.tv_sec, now.tv_sec);
      BOOST_CHECK_EQUAL(entry.requestor.toStringWithPort(), requestor.toStringWithPort());
      BOOST_CHECK_EQUAL(entry.usec, latency);
      BOOST_CHECK_EQUAL(entry.ds.toStringWithPort(), server.toStringWithPort());
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

BOOST_AUTO_TEST_SUITE_END()
