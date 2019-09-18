#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

// Disable this code for gcc 4.8 and lower
#if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ > 8) || !__GNUC__

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


using namespace boost;
using namespace boost::accumulators;

typedef accumulator_set<
  double
  , stats<boost::accumulators::tag::median(with_p_square_quantile),
          boost::accumulators::tag::mean(immediate)
          >
  > acc_t;



BOOST_AUTO_TEST_SUITE(test_dns_random_hh)

BOOST_AUTO_TEST_CASE(test_dns_random_auto_average) {

  ::arg().set("rng")="auto";
  ::arg().set("entropy-source")="/dev/urandom";

  dns_random_init("", true);

  acc_t acc;

  for(unsigned int n=0; n < 100000; ++n)  {
    acc(dns_random(100000)/100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}

BOOST_AUTO_TEST_CASE(test_dns_random_urandom_average) {

  ::arg().set("rng")="urandom";
  ::arg().set("entropy-source")="/dev/urandom";

  dns_random_init("", true);

  acc_t acc;

  for(unsigned int n=0; n < 100000; ++n)  {
    acc(dns_random(100000)/100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}

BOOST_AUTO_TEST_CASE(test_dns_random_garbage) {

  ::arg().set("rng")="garbage";
  ::arg().set("entropy-source")="/dev/urandom";

  BOOST_CHECK_THROW(dns_random_init("", true), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_dns_random_upper_bound) {
  ::arg().set("rng")="auto";
  ::arg().set("entropy-source")="/dev/urandom";

  dns_random_init("", true);

  map<int, bool> seen;
  for(unsigned int n=0; n < 100000; ++n) {
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

#if defined(HAVE_GETRANDOM)
BOOST_AUTO_TEST_CASE(test_dns_random_getrandom_average) {

  ::arg().set("rng")="getrandom";
  ::arg().set("entropy-source")="/dev/urandom";

  dns_random_init("", true);

  acc_t acc;

  for(unsigned int n=0; n < 100000; ++n)  {
    acc(dns_random(100000)/100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}
#endif

#if defined(HAVE_ARC4RANDOM)
BOOST_AUTO_TEST_CASE(test_dns_random_getrandom_average) {

  ::arg().set("rng")="arc4random";
  ::arg().set("entropy-source")="/dev/urandom";

  dns_random_init("", true);

  acc_t acc;

  for(unsigned int n=0; n < 100000; ++n)  {
    acc(dns_random(100000)/100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}
#endif

#if defined(HAVE_RANDOMBYTES_STIR)
BOOST_AUTO_TEST_CASE(test_dns_random_sodium_average) {

  ::arg().set("rng")="sodium";
  ::arg().set("entropy-source")="/dev/urandom";

  dns_random_init("", true);

  acc_t acc;

  for(unsigned int n=0; n < 100000; ++n)  {
    acc(dns_random(100000)/100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}
#endif

#if defined(HAVE_RAND_BYTES)
BOOST_AUTO_TEST_CASE(test_dns_random_openssl_average) {

  ::arg().set("rng")="openssl";
  ::arg().set("entropy-source")="/dev/urandom";

  dns_random_init("", true);

  acc_t acc;

  for(unsigned int n=0; n < 100000; ++n)  {
    acc(dns_random(100000)/100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}
#endif

#if defined(HAVE_KISS_RNG)
BOOST_AUTO_TEST_CASE(test_dns_random_kiss_average) {

  ::arg().set("rng")="kiss";
  ::arg().set("entropy-source")="/dev/urandom";

  dns_random_init("", true);

  acc_t acc;

  for(unsigned int n=0; n < 100000; ++n)  {
    acc(dns_random(100000)/100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);

  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}
#endif


BOOST_AUTO_TEST_SUITE_END()

#endif
