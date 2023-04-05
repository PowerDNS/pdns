#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "mtasker.hh"
#include <fcntl.h>

BOOST_AUTO_TEST_SUITE(mtasker_cc)

static int g_result;

static void doSomething(void* p)
{
  MTasker<>* mt = reinterpret_cast<MTasker<>*>(p);
  int i = 12, o = 0;
  if (mt->waitEvent(i, &o) == 1)
    g_result = o;
}

BOOST_AUTO_TEST_CASE(test_Simple)
{
  MTasker<> mt;
  mt.makeThread(doSomething, &mt);
  struct timeval now;
  gettimeofday(&now, 0);
  bool first = true;
  int o = 24;
  for (;;) {
    while (mt.schedule(&now))
      ;
    if (first) {
      mt.sendEvent(12, &o);
      first = false;
    }
    if (mt.noProcesses())
      break;
  }
  BOOST_CHECK_EQUAL(g_result, o);
}

static const size_t stackSize = 8 * 1024;
static const size_t headroom = 1536; // Decrease to hit stackoverflow

static void doAlmostStackoverflow(void* arg)
{
  auto* mt = reinterpret_cast<MTasker<>*>(arg);
  int localvar[stackSize / sizeof(int) - headroom]; // experimentally derived headroom
  localvar[0] = 0;
  localvar[sizeof(localvar) / sizeof(localvar[0]) - 1] = 12;
  if (mt->waitEvent(localvar[sizeof(localvar) / sizeof(localvar[0]) - 1], &localvar[0]) == 1) {
    g_result = localvar[0];
  }
}

BOOST_AUTO_TEST_CASE(test_AlmostStackOverflow)
{
  MTasker<> mt(stackSize);
  mt.makeThread(doAlmostStackoverflow, &mt);
  struct timeval now;
  gettimeofday(&now, 0);
  bool first = true;
  int o = 25;
  for (;;) {
    while (mt.schedule(&now)) {
      ;
    }
    if (first) {
      mt.sendEvent(12, &o);
      first = false;
    }
    if (mt.noProcesses()) {
      break;
    }
  }
  BOOST_CHECK_EQUAL(g_result, o);
}

#if defined(HAVE_FIBER_SANITIZER) && defined(__APPLE__) && defined(__arm64__)

// This test is buggy on MacOS when compiled with asan. It also causes subsequents tests to report spurious issues.
// So switch it off for now
// See https://github.com/PowerDNS/pdns/issues/12151

BOOST_AUTO_TEST_CASE(test_MtaskerException)
{
  cerr << "test_MtaskerException test disabled on this platform with asan enabled, please fix" << endl;
}

#else

static void willThrow(void* /* p */)
{
  throw std::runtime_error("Help!");
}

BOOST_AUTO_TEST_CASE(test_MtaskerException)
{
  BOOST_CHECK_THROW({
    MTasker<> mt;
    mt.makeThread(willThrow, 0);
    struct timeval now;
    now.tv_sec = now.tv_usec = 0;

    for (;;) {
      mt.schedule(&now);
    }
  },
                    std::exception);
}

#endif // defined(HAVE_FIBER_SANITIZER) && defined(__APPLE__) && defined(__arm64__)

BOOST_AUTO_TEST_SUITE_END()
