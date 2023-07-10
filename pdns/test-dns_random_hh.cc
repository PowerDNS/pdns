#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/std/map.hpp>

#include <boost/accumulators/statistics/median.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics.hpp>

#include "arguments.hh"
#include "dns_random.hh"
#include "namespaces.hh"

using namespace boost::accumulators;

using acc_t = accumulator_set<double, stats<tag::median(with_p_square_quantile), tag::mean(immediate)>>;

BOOST_AUTO_TEST_SUITE(test_dns_random_hh)

const std::vector<string> rndSources = {
  "auto",
  "urandom",
#if defined(HAVE_GETRANDOM)
  "getrandom",
#endif
#if defined(HAVE_ARC4RANDOM)
  "arc4random",
#endif
#if defined(HAVE_RANDOMBYTES_STIR)
  "sodium",
#endif
#if defined(HAVE_RAND_BYTES)
  "openssl",
#endif
#if defined(HAVE_KISS_RNG)
  "kiss",
#endif
};

BOOST_AUTO_TEST_CASE(test_dns_random_garbage)
{
  ::arg().set("rng") = "garbage";
  ::arg().set("entropy-source") = "/dev/urandom";
}

BOOST_AUTO_TEST_CASE(test_dns_random_upper_bound)
{
  ::arg().set("rng") = "auto";
  ::arg().set("entropy-source") = "/dev/urandom";

  map<unsigned int, bool> seen;
  for (unsigned int iteration = 0; iteration < 100000; ++iteration) {
    seen[dns_random(10)] = true;
  }

  BOOST_CHECK_EQUAL(seen[0], true);
  BOOST_CHECK_EQUAL(seen[1], true);
  BOOST_CHECK_EQUAL(seen[2], true);
  BOOST_CHECK_EQUAL(seen[3], true);
  BOOST_CHECK_EQUAL(seen[4], true);
  BOOST_CHECK_EQUAL(seen[5], true);
  BOOST_CHECK_EQUAL(seen[6], true);
  BOOST_CHECK_EQUAL(seen[7], true);
  BOOST_CHECK_EQUAL(seen[8], true);
  BOOST_CHECK_EQUAL(seen[9], true);
  BOOST_CHECK_EQUAL(seen[10], false);
}

static void test_dns_random_avg(const string& source)
{
  ::arg().set("rng") = source;
  ::arg().set("entropy-source") = "/dev/urandom";

  acc_t acc;

  for (unsigned int iteration = 0; iteration < 100000; ++iteration) {
    acc(dns_random(100000) / 100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}

static void test_dns_random_uint32_avg(const string& source)
{
  ::arg().set("rng") = source;
  ::arg().set("entropy-source") = "/dev/urandom";

  acc_t acc;

  for (unsigned int iteration = 0; iteration < 100000; ++iteration) {
    acc(dns_random_uint32() / static_cast<double>(pdns::dns_random_engine::max()));
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}

BOOST_AUTO_TEST_CASE(test_dns_random_average)
{
  for (const auto& source : rndSources) {
    test_dns_random_avg(source);
  }
}

BOOST_AUTO_TEST_CASE(test_dns_random_uint32_average)
{
  for (const auto& source : rndSources) {
    test_dns_random_uint32_avg(source);
  }
}

BOOST_AUTO_TEST_SUITE_END()
