#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

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
    while (mt.schedule(now)) {
    }

    if (first) {
      mt.sendEvent(12, &o);
      first = false;
    }
    if (mt.noProcesses())
      break;
  }
  BOOST_CHECK_EQUAL(g_result, o);
  vector<int> events;
  mt.getEvents(events);
  BOOST_CHECK_EQUAL(events.size(), 0U);
}

struct MTKey
{
  int key;
  shared_ptr<int> ptr;

  bool operator<(const MTKey& /* b */) const
  {
    // We don't want explicit PacketID compare here, but always via predicate class below
    assert(0); // NOLINT: lib
  }
};

struct MTKeyCompare
{
  bool operator()(const std::shared_ptr<MTKey>& lhs, const std::shared_ptr<MTKey>& rhs) const
  {
    return lhs->key < rhs->key;
  }
};

using KeyMT_t = MTasker<std::shared_ptr<MTKey>, int, MTKeyCompare>;

// Test the case of #14807
static void doSomethingKey(void* ptr)
{
  auto* multiTasker = reinterpret_cast<KeyMT_t*>(ptr); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  auto key = std::make_shared<MTKey>();
  key->key = 12;
  key->ptr = std::make_shared<int>(13);
  BOOST_CHECK_EQUAL(key.use_count(), 1U);
  BOOST_CHECK_EQUAL(key->ptr.use_count(), 1U);
  int value = 0;
  if (multiTasker->waitEvent(key, &value) == 1) {
    g_result = value;
  }
  BOOST_CHECK_EQUAL(key.use_count(), 1U);
  BOOST_CHECK_EQUAL(key->key, 12);
  BOOST_REQUIRE(key->ptr != nullptr);
  BOOST_CHECK_EQUAL(key->ptr.use_count(), 1U);
  BOOST_CHECK_EQUAL(*key->ptr, 13);
}

BOOST_AUTO_TEST_CASE(test_SharedPointer)
{
  g_result = 0;
  KeyMT_t multiTasker;
  multiTasker.makeThread(doSomethingKey, &multiTasker);
  timeval now{};
  gettimeofday(&now, nullptr);
  bool first = true;
  int value = 24;
  auto key = std::make_shared<MTKey>();
  key->key = 12;
  key->ptr = std::make_shared<int>(1);
  BOOST_CHECK_EQUAL(key->ptr.use_count(), 1U);
  for (;;) {
    while (multiTasker.schedule(now)) {
    }

    if (first) {
      multiTasker.sendEvent(key, &value);
      BOOST_CHECK_EQUAL(key.use_count(), 1U);
      BOOST_CHECK_EQUAL(key->ptr.use_count(), 1U);
      first = false;
    }
    if (multiTasker.noProcesses()) {
      break;
    }
  }
  BOOST_CHECK_EQUAL(g_result, value);
  vector<std::shared_ptr<MTKey>> events;
  multiTasker.getEvents(events);
  BOOST_CHECK_EQUAL(events.size(), 0U);
  BOOST_CHECK_EQUAL(key.use_count(), 1U);
  BOOST_CHECK_EQUAL(key->ptr.use_count(), 1U);
  BOOST_CHECK_EQUAL(*key->ptr, 1);
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
    while (mt.schedule(now)) {
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
      mt.schedule(now);
    } }, std::exception);
}

BOOST_AUTO_TEST_SUITE_END()
