#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include "sholder.hh"
#include <thread>

using std::string;

struct TestObject
{
  string name;
  uint64_t number;
};

static GlobalStateHolder<TestObject> g_to; 
std::atomic<bool> g_failed;

BOOST_AUTO_TEST_SUITE(test_sholder_hh)

void treader()
{
  auto local = g_to.getLocal();
  for(int n=0; n < 10000000; ++n) {
    auto g = *local;
    if(g.name != std::to_string(g.number)) {
      g_failed=1;
      break;
    }
  }
}

BOOST_AUTO_TEST_CASE(test_sholder) {
  g_to.setState({"1", 1});

  std::thread t1(treader);
  for(unsigned int n=0; n < 1000000; ++n) {
    g_to.setState({std::to_string(n), n});
    g_to.modify([n](TestObject& to) { to.number = 2*n; to.name=std::to_string(to.number);} );
  }
  t1.join();
  BOOST_CHECK_EQUAL(g_failed, 0);
}


BOOST_AUTO_TEST_SUITE_END()

