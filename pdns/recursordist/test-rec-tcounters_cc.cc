#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>

#include <unistd.h>
#include <thread>
#include "dns_random.hh"
#include "rec-tcounters.hh"

static rec::GlobalCounters global;
static thread_local rec::TCounters tlocal(global);

BOOST_AUTO_TEST_SUITE(test_rec_tcounters_cc)

BOOST_AUTO_TEST_CASE(destruct)
{
  global.reset();

  const size_t count = 100000;
  std::thread thread1([] {
    for (size_t i = 0; i < count; i++) {
      ++tlocal.at(rec::Counter::servFails);
    }
  });
  std::thread thread2([] {
    for (size_t i = 0; i < count; i++) {
      ++tlocal.at(rec::Counter::nxDomains);
    }
  });
  thread1.join();
  thread2.join();
  BOOST_CHECK_EQUAL(global.sum(rec::Counter::servFails), count);
  BOOST_CHECK_EQUAL(global.sum(rec::Counter::nxDomains), count);
}

BOOST_AUTO_TEST_CASE(update_fast)
{
  global.reset();

  std::atomic<uint64_t> done{};

  const size_t count = 10000000;
  std::thread thread1([&done] {
    for (size_t i = 0; i < count; i++) {
      ++tlocal.at(rec::Counter::servFails);
      ++tlocal.at(rec::Counter::nxDomains);
      tlocal.at(rec::DoubleWAvgCounter::avgLatencyUsec).add(1.1);
      if (dns_random(10000) == 0) {
        tlocal.updateSnap();
      }
    }
    done++;
  });
  std::thread thread2([&done] {
    for (size_t i = 0; i < count / 2; i++) {
      ++tlocal.at(rec::Counter::servFails);
      ++tlocal.at(rec::Counter::nxDomains);
      tlocal.at(rec::DoubleWAvgCounter::avgLatencyUsec).add(2.2);
      if (dns_random(10000) == 0) {
        tlocal.updateSnap();
      }
    }
    done++;
  });
  std::thread thread3([&done] {
    while (done < 2) {
      auto counts = global.aggregatedSnap();
      BOOST_CHECK_EQUAL(counts.uint64Count[0], counts.uint64Count[1]);
      auto avg = counts.at(rec::DoubleWAvgCounter::avgLatencyUsec).avg;
      BOOST_CHECK(avg == 0.0 || (avg >= 1.1 && avg <= 2.2));
      std::this_thread::yield(); // needed, as otherwise the updates to done might not be spotted under valgrind
    }
  });
  thread1.join();
  thread2.join();
  thread3.join();
  BOOST_CHECK_EQUAL(global.sum(rec::Counter::servFails), count + count / 2);
  BOOST_CHECK_EQUAL(global.sum(rec::Counter::nxDomains), count + count / 2);
  auto avg = global.avg(rec::DoubleWAvgCounter::avgLatencyUsec);
  BOOST_CHECK(avg >= 1.1 && avg <= 2.2);
}

BOOST_AUTO_TEST_CASE(update_with_sleep)
{

  global.reset();

  std::atomic<int> done{};

  const size_t count = 100;
  std::thread thread1([&done] {
    for (size_t i = 0; i < count; i++) {
      ++tlocal.at(rec::Counter::servFails);
      ++tlocal.at(rec::Counter::nxDomains);
      tlocal.at(rec::DoubleWAvgCounter::avgLatencyUsec).add(1.1);
      if (dns_random(10000) == 0) {
        tlocal.updateSnap();
      }
      struct timespec interval{
        0, dns_random(20 * 1000 * 1000)};
      nanosleep(&interval, nullptr);
    }
    done++;
  });
  std::thread thread2([&done] {
    for (size_t i = 0; i < count / 2; i++) {
      ++tlocal.at(rec::Counter::servFails);
      ++tlocal.at(rec::Counter::nxDomains);
      tlocal.at(rec::DoubleWAvgCounter::avgLatencyUsec).add(2.2);
      if (dns_random(10000) == 0) {
        tlocal.updateSnap();
      }
      struct timespec interval{
        0, dns_random(40 * 1000 * 1000)};
      nanosleep(&interval, nullptr);
    }
    done++;
  });
  std::thread thread3([&done] {
    while (done < 2) {
      auto counts = global.aggregatedSnap();
      BOOST_CHECK_EQUAL(counts.uint64Count[0], counts.uint64Count[1]);
      auto avg = counts.at(rec::DoubleWAvgCounter::avgLatencyUsec).avg;
      // std::cerr << avg << std::endl;
      BOOST_CHECK(avg == 0.0 || (avg >= 1.1 && avg <= 2.2));
      struct timespec interval{
        0, dns_random(80 * 1000 * 1000)};
      nanosleep(&interval, nullptr);
    }
  });
  thread1.join();
  thread2.join();
  thread3.join();
  BOOST_CHECK_EQUAL(global.sum(rec::Counter::servFails), count + count / 2);
  BOOST_CHECK_EQUAL(global.sum(rec::Counter::nxDomains), count + count / 2);
  auto avg = global.avg(rec::DoubleWAvgCounter::avgLatencyUsec);
  BOOST_CHECK(avg >= 1.1 && avg <= 2.2);
}

BOOST_AUTO_TEST_SUITE_END()
