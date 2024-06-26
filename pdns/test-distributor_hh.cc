#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cstdlib>
#include <unistd.h>
#include <boost/test/unit_test.hpp>
#include "distributor.hh"
#include "dnspacket.hh"
#include "namespaces.hh"

bool g_doGssTSIG = false;

BOOST_AUTO_TEST_SUITE(test_distributor_hh)

struct Question
{
  int q;
  DTime d_dt;
  DNSName qdomain;
  QType qtype;
  std::unique_ptr<DNSPacket> replyPacket()
  {
    return make_unique<DNSPacket>(false);
  }
  void cleanupGSS(int){}
};

struct Backend
{
  std::unique_ptr<DNSPacket> question(Question&)
  {
    return make_unique<DNSPacket>(true);
  }
};

static std::atomic<int> g_receivedAnswers;
static void report(std::unique_ptr<DNSPacket>& /* A */, int /* B */)
{
  g_receivedAnswers++;
}

BOOST_AUTO_TEST_CASE(test_distributor_basic) {
  ::arg().set("overload-queue-length","Maximum queuelength moving to packetcache only")="0";
  ::arg().set("max-queue-length","Maximum queuelength before considering situation lost")="5000";
  ::arg().set("queue-limit","Maximum number of milliseconds to queue a query")="1500";
  S.declare("servfail-packets","Number of times a server-failed packet was sent out");
  S.declare("timedout-packets", "timedout-packets");

  auto d=Distributor<DNSPacket, Question, Backend>::Create(2);

  int n;
  for(n=0; n < 100; ++n)  {
    Question q;
    q.d_dt.set();
    d->question(q, report);
  }
  sleep(1);
  BOOST_CHECK_EQUAL(n, g_receivedAnswers);
};

struct BackendSlow
{
  std::unique_ptr<DNSPacket> question([[maybe_unused]] Question& query)
  {
    if (d_shouldSleep) {
      /* only sleep once per distributor thread, otherwise
         we are sometimes destroyed before picking up the queued
         queries, triggering a memory leak reported by Leak Sanitizer */
      std::this_thread::sleep_for(std::chrono::seconds(1));
      d_shouldSleep = false;
    }
    return make_unique<DNSPacket>(true);
  }
private:
  bool d_shouldSleep{true};
};

static std::atomic<size_t> s_receivedAnswers;
static void report1(std::unique_ptr<DNSPacket>& /* A */, int /* B */)
{
  s_receivedAnswers++;
}

BOOST_AUTO_TEST_CASE(test_distributor_queue) {
  ::arg().set("overload-queue-length","Maximum queuelength moving to packetcache only")="0";
  ::arg().set("max-queue-length","Maximum queuelength before considering situation lost")="1000";
  ::arg().set("queue-limit","Maximum number of milliseconds to queue a query")="1500";
  S.declare("servfail-packets","Number of times a server-failed packet was sent out");
  S.declare("timedout-packets", "timedout-packets");

  s_receivedAnswers.store(0);
  auto* distributor = Distributor<DNSPacket, Question, BackendSlow>::Create(2);

  size_t queued = 0;
  BOOST_CHECK_EXCEPTION( {
    // bound should be higher than max-queue-length
    const size_t bound = 2000;
    for (size_t idx = 0; idx < bound; ++idx)  {
      Question query;
      query.d_dt.set();
      ++queued;
      distributor->question(query, report1);
    }
    }, DistributorFatal, [](DistributorFatal) { return true; });

  BOOST_CHECK_GT(queued, 1000U);

  // now we want to make sure that all queued queries have been processed
  // otherwise LeakSanitizer will report a leak, but we are only willing to
  // wait up to 3 seconds (3000 milliseconds)
  size_t remainingMs = 3000;
  while (s_receivedAnswers.load() < queued && remainingMs > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    remainingMs -= 10;
  }
};

struct BackendDies
{
  BackendDies()
  {
    d_ourcount=s_count++;
  }
  ~BackendDies()
  {
  }
  std::unique_ptr<DNSPacket> question(Question& /* q */)
  {
    //  cout<<"Q: "<<q->qdomain<<endl;
    if(!d_ourcount && ++d_count == 10) {
      // cerr<<"Going.. down!"<<endl;
      throw runtime_error("kill");
    }
    return make_unique<DNSPacket>(true);
  }
  static std::atomic<int> s_count;
  int d_count{0};
  int d_ourcount;
};

std::atomic<int> BackendDies::s_count;

std::atomic<int> g_receivedAnswers2;

static void report2(std::unique_ptr<DNSPacket>& /* A */, int /* B */)
{
  g_receivedAnswers2++;
}


BOOST_AUTO_TEST_CASE(test_distributor_dies) {
  ::arg().set("overload-queue-length","Maximum queuelength moving to packetcache only")="0";
  ::arg().set("max-queue-length","Maximum queuelength before considering situation lost")="5000";
  ::arg().set("queue-limit","Maximum number of milliseconds to queue a query")="1500";
  S.declare("servfail-packets","Number of times a server-failed packet was sent out");
  S.declare("timedout-packets", "timedout-packets");

  auto d=Distributor<DNSPacket, Question, BackendDies>::Create(10);

  try {
    for(int n=0; n < 100; ++n)  {
      Question q;
      q.d_dt.set();
      q.qdomain=DNSName(std::to_string(n));
      q.qtype = QType(QType::A);
      d->question(q, report2);
    }

    sleep(1);
    cerr<<"Queued: "<<d->getQueueSize()<<endl;
    cerr<<"Received: "<<g_receivedAnswers2<<endl;
  }
  catch(std::exception& e) {
    cerr<<e.what()<<endl;
  }
  catch(PDNSException &pe) {
    cerr<<pe.reason<<endl;
  }
};



BOOST_AUTO_TEST_SUITE_END();
