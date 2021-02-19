#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "histogram.hh"

BOOST_AUTO_TEST_SUITE(histogram_hh)

BOOST_AUTO_TEST_CASE(test_simple) {
  auto h = pdns::AtomicHistogram<uint64_t>("myname-", {1, 3, 5, 10, 100});

  h(0);
  h(1);
  h(1);
  h(3);
  h(4);
  h(100);
  h(101);
  h(-1);

  auto data = h.getRawData();
  BOOST_CHECK_EQUAL(data.size(), 6U);
  uint64_t expected[] = { 3, 1, 1, 0, 1, 2};
  size_t i = 0;
  for (auto e : expected) {
	BOOST_CHECK_EQUAL(data[i++].d_count, e);
  }

  auto c = h.getCumulativeCounts();
  BOOST_CHECK_EQUAL(data.size(), 6U);
  uint64_t cexpected[] = { 3, 4, 5, 5, 6, 8};
  i = 0;
  for (auto e : cexpected) {
	BOOST_CHECK_EQUAL(c[i++], e);
  }
}

BOOST_AUTO_TEST_SUITE_END()
