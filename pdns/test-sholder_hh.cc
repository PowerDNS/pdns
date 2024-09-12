#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include "sholder.hh"
#include <thread>

using std::string;

struct TestObject
{
  string name;
  uint64_t number{0};
};

static GlobalStateHolder<TestObject> s_to;
static std::atomic<bool> s_failed;

BOOST_AUTO_TEST_SUITE(test_sholder_hh)

static void treader()
{
  auto local = s_to.getLocal();
  for (uint64_t counter = 0; counter < 10000000U; ++counter) {
    auto copy = *local;
    if (copy.name != std::to_string(copy.number)) {
      s_failed.store(true);
      break;
    }
  }
}

BOOST_AUTO_TEST_CASE(test_sholder)
{
  s_to.setState({"1", 1});

  std::thread thread1(treader);
  for (uint64_t counter = 0; counter < 1000000U; ++counter) {
    s_to.setState({std::to_string(counter), counter});
    s_to.modify([counter](TestObject& toValue) { toValue.number = 2*counter; toValue.name = std::to_string(toValue.number); });
  }
  thread1.join();
  BOOST_CHECK_EQUAL(s_failed, 0);
}

BOOST_AUTO_TEST_SUITE_END()
