#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "lock.hh"
#include <thread>

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_lock_hh)

static std::vector<std::unique_ptr<pthread_rwlock_t> > g_locks;

static void lthread()
{
  std::vector<ReadLock> rlocks;
  for(auto& pp : g_locks)
    rlocks.emplace_back(&*pp);
  
}

BOOST_AUTO_TEST_CASE(test_pdns_lock)
{
  for(unsigned int n=0; n < 1000; ++n) {
    auto p = make_unique<pthread_rwlock_t>();
    pthread_rwlock_init(p.get(), 0);
    g_locks.emplace_back(std::move(p));
  }

  std::vector<ReadLock> rlocks;
  for(auto& pp : g_locks)
    rlocks.emplace_back(&*pp);

  std::thread thr(lthread);
  thr.join();
  rlocks.clear();

  std::vector<WriteLock> wlocks;
  for(auto& pp : g_locks)
    wlocks.emplace_back(&*pp);

  // on macOS, this TryReadLock throws (EDEADLK) instead of simply failing
  // so we catch the exception and consider that success for this test
  bool gotit = false;
  try {
    TryReadLock trl(&*g_locks[0]);
    gotit = trl.gotIt();
  }
  catch(const PDNSException &e) {
    gotit = false;
  }
  BOOST_CHECK(!gotit);

  wlocks.clear();
  TryReadLock trl2(&*g_locks[0]);
  BOOST_CHECK(trl2.gotIt());
  
  
}

BOOST_AUTO_TEST_SUITE_END()
