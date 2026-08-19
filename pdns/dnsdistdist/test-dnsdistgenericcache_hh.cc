#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include <thread>
#include "iputils.hh"
#include "generic-cache.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdistgenericcache_hh)

struct TestStruct
{
  std::string value;
  time_t validity;
};

static void test_genericcache_insertion_removal(GenericCache<std::string, std::string>& cache)
{
  size_t counter = 0;
  for (counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter);
    std::string value = "Value for key: " + std::to_string(counter);
    bool found = cache.contains(key);
    BOOST_CHECK_EQUAL(found, false);

    cache.insert(key, value);

    std::string readValue;
    found = cache.getValue(key, readValue);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK_EQUAL(value, readValue);
  }

  BOOST_CHECK_EQUAL(cache.getSize(), counter);

  size_t deleted = 0;
  size_t delcounter = 0;
  for (delcounter = 0; delcounter < counter / 1000; ++delcounter) {
    std::string value = "Value for key: " + std::to_string(delcounter);
    auto removed = cache.expungeByCondition([&value](const std::string& storedValue) {
      return storedValue == value;
    });
    BOOST_CHECK_EQUAL(removed, 1U);
    deleted += removed;
  }
  BOOST_CHECK_EQUAL(cache.getSize(), counter - deleted);

  for (; delcounter < counter / 500; ++delcounter) {
    std::string key = std::to_string(delcounter);
    auto removed = cache.remove(key);
    BOOST_CHECK_EQUAL(removed, true);
    deleted++;
  }
  BOOST_CHECK_EQUAL(cache.getSize(), counter - deleted);

  size_t matches = 0;
  size_t expected = counter - deleted;
  for (; delcounter < counter; ++delcounter) {
    std::string key = std::to_string(delcounter);
    if (cache.contains(key)) {
      matches++;
    }
  }

  BOOST_CHECK_EQUAL(matches, expected);

  auto remaining = cache.getSize();
  auto removed = cache.expunge();
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);
  BOOST_CHECK_EQUAL(removed, remaining);

  /* nothing to remove */
  BOOST_CHECK_EQUAL(cache.expunge(), 0U);
}

static void test_genericcachefilter_insertion_removal(GenericFilterInterface<std::string>& cache)
{
  size_t counter = 0;
  for (counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter);
    bool found = cache.contains(key);
    BOOST_CHECK_EQUAL(found, false);

    cache.insertKey(key);

    found = cache.contains(key);
    BOOST_CHECK_EQUAL(found, true);
  }

  BOOST_CHECK_EQUAL(cache.getSize(), counter);

  size_t deleted = 0;
  size_t delcounter = 0;
  for (delcounter = 0; delcounter < counter / 1000; ++delcounter) {
    std::string key = std::to_string(delcounter);
    auto removed = cache.remove(key);
    BOOST_CHECK_EQUAL(removed, true);
    deleted++;
  }
  BOOST_CHECK_EQUAL(cache.getSize(), counter - deleted);

  size_t matches = 0;
  size_t expected = counter - deleted;
  for (; delcounter < counter; ++delcounter) {
    std::string key = std::to_string(delcounter);
    if (cache.contains(key)) {
      matches++;
    }
  }

  BOOST_CHECK_EQUAL(matches, expected);

  auto remaining = cache.getSize();
  auto removed = cache.expunge();
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);
  BOOST_CHECK_EQUAL(removed, remaining);

  /* nothing to remove */
  BOOST_CHECK_EQUAL(cache.expunge(), 0U);
}

BOOST_AUTO_TEST_CASE(test_GenericCacheSimple)
{
  const GenericCache<std::string, std::string>::CacheSettings settings{
    .d_maxEntries = 150000};
  GenericCache<std::string, std::string> cache(settings);
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  test_genericcache_insertion_removal(cache);
}

BOOST_AUTO_TEST_CASE(test_GenericCacheSharded)
{
  const GenericCache<std::string, std::string>::CacheSettings settings{
    .d_shardCount = 10,
    .d_maxEntries = 150000};
  GenericCache<std::string, std::string> cache(settings);
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  test_genericcache_insertion_removal(cache);
}

BOOST_AUTO_TEST_CASE(test_GenericCacheAsFilterSimple)
{
  const GenericCache<std::string, std::string>::CacheSettings settings{
    .d_maxEntries = 150000};
  GenericCache<std::string, std::string> cache(settings);
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  test_genericcachefilter_insertion_removal(cache);
}

BOOST_AUTO_TEST_CASE(test_GenericCacheAsFilterSharded)
{
  const GenericCache<std::string, std::string>::CacheSettings settings{
    .d_shardCount = 10,
    .d_maxEntries = 150000};
  GenericCache<std::string, std::string> cache(settings);
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  test_genericcachefilter_insertion_removal(cache);
}

BOOST_AUTO_TEST_CASE(test_GenericCacheSimpleLru)
{
  const GenericCache<std::string, std::string>::CacheSettings settings{
    .d_lruEnabled = true,
    .d_maxEntries = 100000};
  GenericCache<std::string, std::string> cache(settings);
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  size_t counter = 0;
  for (counter = 0; counter < 150000; ++counter) {
    std::string key = std::to_string(counter);
    std::string value = "Value for key: " + std::to_string(counter);
    bool found = cache.contains(key);
    BOOST_CHECK_EQUAL(found, false);

    cache.insert(key, value);

    std::string readValue;
    found = cache.getValue(key, readValue);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK_EQUAL(value, readValue);
  }

  BOOST_CHECK_EQUAL(cache.getSize(), settings.d_maxEntries);

  for (counter = 0; counter < 150000; ++counter) {
    std::string key = std::to_string(counter);
    bool found = cache.contains(key);
    if (counter < 50000) {
      BOOST_CHECK_EQUAL(found, false);
    }
    else {
      BOOST_CHECK_EQUAL(found, true);
    }
  }
}

BOOST_AUTO_TEST_CASE(test_GenericCacheSimpleTtl)
{
  const GenericCache<std::string, std::string>::CacheSettings settings{
    .d_ttlEnabled = true,
    .d_ttl = 100,
    .d_maxEntries = 100000};
  GenericCache<std::string, std::string> cache(settings);
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  size_t counter = 0;
  for (counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter);
    std::string value = "Value for key: " + std::to_string(counter);
    bool found = cache.contains(key);
    BOOST_CHECK_EQUAL(found, false);

    cache.insert(key, value);

    std::string readValue;
    found = cache.getValue(key, readValue);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK_EQUAL(value, readValue);
  }

  BOOST_CHECK_EQUAL(cache.getSize(), settings.d_maxEntries);

  time_t now = time(nullptr);
  size_t removed = cache.purgeExpired(0, now);
  BOOST_CHECK_EQUAL(removed, 0);

  now += settings.d_ttl + 1;

  removed = cache.purgeExpired(0, now);
  BOOST_CHECK_EQUAL(removed, settings.d_maxEntries);
}

BOOST_AUTO_TEST_CASE(test_GenericCacheCustomValidity)
{
  const GenericCache<std::string, TestStruct, std::hash<std::string>, &TestStruct::validity>::CacheSettings settings{
    .d_maxEntries = 100000};
  GenericCache<std::string, TestStruct, std::hash<std::string>, &TestStruct::validity> cache(settings);
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  size_t counter = 0;
  for (counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter);
    std::string value = "Value for key: " + std::to_string(counter);
    bool found = cache.contains(key);
    BOOST_CHECK_EQUAL(found, false);

    cache.insert(key, {value, 0});

    TestStruct readValue;
    found = cache.getValue(key, readValue);
    BOOST_CHECK_EQUAL(found, false);
  }

  BOOST_CHECK_EQUAL(cache.getSize(), 0);
}

BOOST_AUTO_TEST_CASE(test_GenericCacheCapacityCheck)
{
  const GenericCache<std::string, std::string>::CacheSettings settings{
    .d_maxEntries = 100000};
  GenericCache<std::string, std::string> cache(settings);
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  for (size_t counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter);
    std::string value = "Value for key: " + std::to_string(counter);
    bool found = cache.contains(key);
    BOOST_CHECK_EQUAL(found, false);
    bool hasCapacity = cache.hasCapacityFor(key);
    BOOST_CHECK_EQUAL(hasCapacity, true);

    cache.insert(key, value);

    std::string readValue;
    found = cache.getValue(key, readValue);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK_EQUAL(value, readValue);
  }

  BOOST_CHECK_EQUAL(cache.getSize(), 100000);
  BOOST_CHECK_EQUAL(cache.hasCapacityFor("100000"), false);
  cache.remove("99999");
  BOOST_CHECK_EQUAL(cache.hasCapacityFor("100000"), true);
}

const GenericCache<std::string, std::string>::CacheSettings s_localCacheSettings{
  .d_maxEntries = 500000,
  .d_deferrableInsertLock = true};
static GenericCache<std::string, std::string> s_localCache(s_localCacheSettings);

static void threadMangler(unsigned int offset)
{
  for (unsigned int counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter + offset);
    std::string value = "Value for key: " + std::to_string(counter + offset);
    s_localCache.insert(key, value);
  }
}

static std::atomic<uint64_t> s_missing{0};

static void threadReader(unsigned int offset)
{
  ComboAddress remote;
  for (unsigned int counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter + offset);
    bool found = s_localCache.contains(key);
    if (!found) {
      s_missing++;
    }
  }
}

BOOST_AUTO_TEST_CASE(test_GenericCacheThreaded)
{
  std::vector<std::thread> threads;
  threads.reserve(4);
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back(threadMangler, i * 1000000UL);
  }

  for (auto& thr : threads) {
    thr.join();
  }

  threads.clear();

  BOOST_CHECK_EQUAL(s_localCache.getSize() + s_localCache.getStats().d_deferredInserts, 400000U);

  for (int i = 0; i < 4; ++i) {
    threads.emplace_back(threadReader, i * 1000000UL);
  }

  for (auto& thr : threads) {
    thr.join();
  }

  BOOST_CHECK((s_localCache.getStats().d_deferredInserts + s_localCache.getStats().d_deferredLookups) >= s_missing.load());
}

BOOST_AUTO_TEST_CASE(test_GenericCacheExceptions)
{
  using cache_t = GenericCache<std::string, std::string>;
  BOOST_CHECK_THROW(cache_t({.d_maxEntries = 0}), std::runtime_error);
  BOOST_REQUIRE_NO_THROW(cache_t({.d_ttlEnabled = true, .d_maxEntries = 1}));
  using custom_ttl_cache_t = GenericCache<std::string, TestStruct, std::hash<std::string>, &TestStruct::validity>;
  BOOST_CHECK_THROW(custom_ttl_cache_t({.d_ttlEnabled = true, .d_maxEntries = 1}), std::runtime_error);
}

static void test_bloomfilter_insertion(BloomFilter& filter)
{
  size_t counter = 0;
  for (counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter);
    bool found = filter.contains(key);
    BOOST_CHECK_EQUAL(found, false);

    filter.insertKey(key);

    found = filter.contains(key);
    BOOST_CHECK_EQUAL(found, true);
  }

  BOOST_CHECK_EQUAL(filter.getSize(), counter);
}

static void test_bloomfilter_insertion_with_unused_value(BloomFilter& filter)
{
  size_t counter = 0;
  for (counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter);
    bool found = filter.contains(key);
    BOOST_CHECK_EQUAL(found, false);

    std::optional<LuaAny> value{"test-value"};
    filter.insert(key, value);

    std::optional<LuaAny> readValue;
    found = filter.getValue(key, readValue);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!readValue.has_value());
  }

  BOOST_CHECK_EQUAL(filter.getSize(), counter);
}

BOOST_AUTO_TEST_CASE(test_BloomFilterSimple)
{
  BloomFilter cache({});
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  test_bloomfilter_insertion(cache);
}

BOOST_AUTO_TEST_CASE(test_BloomFilterSimpleAsCache)
{
  BloomFilter cache({});
  BOOST_CHECK_EQUAL(cache.getSize(), 0U);

  test_bloomfilter_insertion_with_unused_value(cache);
}

static BloomFilter s_bloom({});

static void bloomThreadMangler(unsigned int offset)
{
  for (unsigned int counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter + offset);
    s_bloom.insertKey(key);
  }
}

static std::atomic<uint64_t> s_bloomMissing{0};

static void bloomThreadReader(unsigned int offset)
{
  ComboAddress remote;
  for (unsigned int counter = 0; counter < 100000; ++counter) {
    std::string key = std::to_string(counter + offset);
    bool found = s_bloom.contains(key);
    if (!found) {
      s_missing++;
    }
  }
}

BOOST_AUTO_TEST_CASE(test_BloomFilterThreaded)
{
  std::vector<std::thread> threads;
  threads.reserve(4);
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back(bloomThreadMangler, i * 1000000UL);
  }

  for (auto& thr : threads) {
    thr.join();
  }

  threads.clear();

  BOOST_CHECK_EQUAL(s_bloom.getSize(), 400000U);

  for (int i = 0; i < 4; ++i) {
    threads.emplace_back(bloomThreadReader, i * 1000000UL);
  }

  for (auto& thr : threads) {
    thr.join();
  }

  BOOST_CHECK_EQUAL(s_bloomMissing.load(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
