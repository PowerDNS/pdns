#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <unistd.h>
#include <boost/test/unit_test.hpp>
#include "distributor.hh"
#include "dnspacket.hh"
#include "namespaces.hh" 

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
};

struct Backend
{
  std::unique_ptr<DNSPacket> question(Question&)
  {
    return make_unique<DNSPacket>(true);
  }
};

static std::atomic<int> g_receivedAnswers;
static void report(std::unique_ptr<DNSPacket>& A)
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
  std::unique_ptr<DNSPacket> question(Question&)
  {
    sleep(1);
    return make_unique<DNSPacket>(true);
  }
};

static std::atomic<int> g_receivedAnswers1;
static void report1(std::unique_ptr<DNSPacket>& A)
{
  g_receivedAnswers1++;
}

BOOST_AUTO_TEST_CASE(test_distributor_queue) {
  ::arg().set("overload-queue-length","Maximum queuelength moving to packetcache only")="0";
  ::arg().set("max-queue-length","Maximum queuelength before considering situation lost")="1000";
  ::arg().set("queue-limit","Maximum number of milliseconds to queue a query")="1500";
  S.declare("servfail-packets","Number of times a server-failed packet was sent out");
  S.declare("timedout-packets", "timedout-packets");

  auto d=Distributor<DNSPacket, Question, BackendSlow>::Create(2);

  BOOST_CHECK_EXCEPTION( {
    int n;
    // bound should be higher than max-queue-length
    for(n=0; n < 2000; ++n)  {
      Question q;
      q.d_dt.set(); 
      d->question(q, report1);
    }
    }, DistributorFatal, [](DistributorFatal) { return true; });
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
  std::unique_ptr<DNSPacket> question(Question& q)
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

static void report2(std::unique_ptr<DNSPacket>& A)
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
