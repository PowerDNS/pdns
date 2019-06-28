
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <thread>
#include <boost/test/unit_test.hpp>

#include "mplexer.hh"
#include "misc.hh"

BOOST_AUTO_TEST_SUITE(mplexer)

BOOST_AUTO_TEST_CASE(test_MPlexer) {
  auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());
  BOOST_REQUIRE(mplexer != nullptr);

  struct timeval now;
  int ready = mplexer->run(&now, 100);
  BOOST_CHECK_EQUAL(ready, 0);

  std::vector<int> readyFDs;
  mplexer->getAvailableFDs(readyFDs, 0);
  BOOST_CHECK_EQUAL(readyFDs.size(), 0);

  auto timeouts = mplexer->getTimeouts(now);
  BOOST_CHECK_EQUAL(timeouts.size(), 0);

  int pipes[2];
  int res = pipe(pipes);
  BOOST_REQUIRE_EQUAL(res, 0);
  BOOST_REQUIRE_EQUAL(setNonBlocking(pipes[0]), true);
  BOOST_REQUIRE_EQUAL(setNonBlocking(pipes[1]), true);

  /* let's declare a TTD that expired 5s ago */
  struct timeval ttd = now;
  ttd.tv_sec -= 5;

  bool writeCBCalled = false;
  auto writeCB = [](int fd, FDMultiplexer::funcparam_t param) {
                        auto calledPtr = boost::any_cast<bool*>(param);
                        BOOST_REQUIRE(calledPtr != nullptr);
                        *calledPtr = true;
                 };
  mplexer->addWriteFD(pipes[1],
                      writeCB,
                      &writeCBCalled,
                      &ttd);
  /* we can't add it twice */
  BOOST_CHECK_THROW(mplexer->addWriteFD(pipes[1],
                                        writeCB,
                                        &writeCBCalled,
                                        &ttd),
                    FDMultiplexerException);

  readyFDs.clear();
  mplexer->getAvailableFDs(readyFDs, 0);
  BOOST_REQUIRE_EQUAL(readyFDs.size(), 1);
  BOOST_CHECK_EQUAL(readyFDs.at(0), pipes[1]);

  ready = mplexer->run(&now, 100);
  BOOST_CHECK_EQUAL(ready, 1);
  BOOST_CHECK_EQUAL(writeCBCalled, true);

  /* no read timeouts */
  timeouts = mplexer->getTimeouts(now, false);
  BOOST_CHECK_EQUAL(timeouts.size(), 0);
  /* but we should have a write one */
  timeouts = mplexer->getTimeouts(now, true);
  BOOST_REQUIRE_EQUAL(timeouts.size(), 1);
  BOOST_CHECK_EQUAL(timeouts.at(0).first, pipes[1]);

  /* can't remove from the wrong type of FD */
  BOOST_CHECK_THROW(mplexer->removeReadFD(pipes[1]), FDMultiplexerException);
  mplexer->removeWriteFD(pipes[1]);
  /* can't remove a non-existing FD */
  BOOST_CHECK_THROW(mplexer->removeWriteFD(pipes[0]), FDMultiplexerException);
  BOOST_CHECK_THROW(mplexer->removeWriteFD(pipes[1]), FDMultiplexerException);

  readyFDs.clear();
  mplexer->getAvailableFDs(readyFDs, 0);
  BOOST_REQUIRE_EQUAL(readyFDs.size(), 0);

  ready = mplexer->run(&now, 100);
  BOOST_CHECK_EQUAL(ready, 0);

  bool readCBCalled = false;
  auto readCB = [](int fd, FDMultiplexer::funcparam_t param) {
                        auto calledPtr = boost::any_cast<bool*>(param);
                        BOOST_REQUIRE(calledPtr != nullptr);
                        *calledPtr = true;
                };
  mplexer->addReadFD(pipes[0],
                     readCB,
                     &readCBCalled,
                     &ttd);

  /* not ready for reading yet */
  readyFDs.clear();
  mplexer->getAvailableFDs(readyFDs, 0);
  BOOST_REQUIRE_EQUAL(readyFDs.size(), 0);

  ready = mplexer->run(&now, 100);
  BOOST_CHECK_EQUAL(ready, 0);
  BOOST_CHECK_EQUAL(readCBCalled, false);

  /* let's make the pipe readable */
  BOOST_REQUIRE_EQUAL(write(pipes[1], "0", 1), 1);

  readyFDs.clear();
  mplexer->getAvailableFDs(readyFDs, 0);
  BOOST_REQUIRE_EQUAL(readyFDs.size(), 1);
  BOOST_CHECK_EQUAL(readyFDs.at(0), pipes[0]);

  ready = mplexer->run(&now, 100);
  BOOST_CHECK_EQUAL(ready, 1);
  BOOST_CHECK_EQUAL(readCBCalled, true);

  /* add back the write FD */
  mplexer->addWriteFD(pipes[1],
                      writeCB,
                      &writeCBCalled,
                      &ttd);

  /* both should be available */
  readyFDs.clear();
  mplexer->getAvailableFDs(readyFDs, 0);
  if (readyFDs.size() == 1) {
    /* something is wrong, we need some debug infos */
    cerr<<"FDMultiPlexer implementation is "<<mplexer->getName()<<endl;
    cerr<<"Watching "<<mplexer->getWatchedFDCount(false)<<" FDs for read and "<<mplexer->getWatchedFDCount(true)<<" for write"<<endl;
    cerr<<"pipes[0] is "<<pipes[0]<<endl;
    cerr<<"pipes[1] is "<<pipes[1]<<endl;
    cerr<<"The file descripttor returned as ready is "<<readyFDs.at(0)<<endl;
    char buffer[2];
    ssize_t res = read(pipes[0], &buffer[0], sizeof(buffer));
    int saved = errno;
    cerr<<"Reading from pipes[0] returns "<<res<<endl;
    if (res == -1) {
      cerr<<"errno is "<<saved<<endl;
    }
    res = write(pipes[1], "0", 1);
    saved = errno;
    cerr<<"Writing to pipes[1] returns "<<res<<endl;
    if (res == -1) {
      cerr<<"errno is "<<saved<<endl;
    }
  }
  BOOST_REQUIRE_EQUAL(readyFDs.size(), 2);

  readCBCalled = false;
  writeCBCalled = false;
  ready = mplexer->run(&now, 100);
  BOOST_CHECK_EQUAL(ready, 2);
  BOOST_CHECK_EQUAL(readCBCalled, true);
  BOOST_CHECK_EQUAL(writeCBCalled, true);

  /* both the read and write FD should be reported */
  timeouts = mplexer->getTimeouts(now, false);
  BOOST_REQUIRE_EQUAL(timeouts.size(), 1);
  BOOST_CHECK_EQUAL(timeouts.at(0).first, pipes[0]);
  timeouts = mplexer->getTimeouts(now, true);
  BOOST_REQUIRE_EQUAL(timeouts.size(), 1);
  BOOST_CHECK_EQUAL(timeouts.at(0).first, pipes[1]);

  struct timeval past = ttd;
  /* so five seconds before the actual TTD */
  past.tv_sec -= 5;

  /* no read timeouts */
  timeouts = mplexer->getTimeouts(past, false);
  BOOST_CHECK_EQUAL(timeouts.size(), 0);
  /* and we should not have a write one either */
  timeouts = mplexer->getTimeouts(past, true);
  BOOST_CHECK_EQUAL(timeouts.size(), 0);

  /* update the timeouts to now, they should not be reported anymore */
  mplexer->setReadTTD(pipes[0], now, 0);
  mplexer->setWriteTTD(pipes[1], now, 0);
  timeouts = mplexer->getTimeouts(now, false);
  BOOST_REQUIRE_EQUAL(timeouts.size(), 0);
  timeouts = mplexer->getTimeouts(now, true);
  BOOST_REQUIRE_EQUAL(timeouts.size(), 0);

  /* put it back into the past */
  mplexer->setReadTTD(pipes[0], now, -5);
  mplexer->setWriteTTD(pipes[1], now, -5);
  timeouts = mplexer->getTimeouts(now, false);
  BOOST_REQUIRE_EQUAL(timeouts.size(), 1);
  BOOST_CHECK_EQUAL(timeouts.at(0).first, pipes[0]);
  timeouts = mplexer->getTimeouts(now, true);
  BOOST_REQUIRE_EQUAL(timeouts.size(), 1);
  BOOST_CHECK_EQUAL(timeouts.at(0).first, pipes[1]);

  mplexer->removeReadFD(pipes[0]);
  mplexer->removeWriteFD(pipes[1]);

  /* clean up */
  close(pipes[0]);
  close(pipes[1]);
}


BOOST_AUTO_TEST_SUITE_END()
