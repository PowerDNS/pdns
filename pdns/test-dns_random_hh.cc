#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/std/map.hpp>
#include <boost/foreach.hpp>
#include <boost/accumulators/statistics/median.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics.hpp>

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

BOOST_AUTO_TEST_CASE(test_dns_random_average) {
  dns_random_init("/dev/urandom");
  acc_t acc;


  for(unsigned int n=0; n < 100000; ++n)  {
    acc(dns_random(100000)/100000.0);
  }
  BOOST_CHECK_CLOSE(0.5, median(acc), 2.0); // within 2%
  BOOST_CHECK_CLOSE(0.5, mean(acc), 2.0);
  
  // please add covariance tests, chi-square, Kolmogorov-Smirnov
}

BOOST_AUTO_TEST_SUITE_END()
