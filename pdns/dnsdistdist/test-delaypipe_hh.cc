#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "delaypipe.hh"

BOOST_AUTO_TEST_SUITE(test_delaypipe_hh);

BOOST_AUTO_TEST_CASE(test_object_pipe) {
  ObjectPipe<int> op;
  for(int n=0; n < 100; ++n)
    op.write(n);

  int i;
  for(int n=0; n < 100; ++n) {
    bool res=op.read(&i);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(n, i);
  }

  op.close();
  BOOST_CHECK_EQUAL(op.read(&i), false);

};

int done=0;
BOOST_AUTO_TEST_CASE(test_delay_pipe_small) {
  done=0;
  struct Work
  {
    int i;
    void operator()()
    {
      ++done;
    }
  };
  DelayPipe<Work> dp;
  int n;
  for(n=0; n < 5; ++n) {
    Work w{n};
    dp.submit(w, 500);
  }
  BOOST_CHECK_EQUAL(done, 0);

  for(; n < 10; ++n) {
    Work w{n};
    dp.submit(w, 1200);
  }
  sleep(1);
  BOOST_CHECK_EQUAL(done, 5);
  sleep(1);
  BOOST_CHECK_EQUAL(done, n);

};

BOOST_AUTO_TEST_CASE(test_delay_pipe_big) {  
  done=0;
  struct Work
  {
    int i;
    void operator()()
    {
      ++done;
    }
  };
  DelayPipe<Work> dp;
  int n;
  for(n=0; n < 1000000; ++n) {
    Work w{n};
    dp.submit(w, 100);
  }

  sleep(1);
  BOOST_CHECK_EQUAL(done, n);
};


BOOST_AUTO_TEST_SUITE_END();
