/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string>
#include <deque>
#include <queue>
#include <vector>
#include <thread>
#include "threadname.hh"
#include <unistd.h>

#include "channel.hh"
#include "logger.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "pdnsexception.hh"
#include "arguments.hh"
#include <atomic>
#include "statbag.hh"
#include "gss_context.hh"

extern StatBag S;

/** the Distributor template class enables you to multithread slow question/answer 
    processes. 
    
    Questions are posed to the Distributor, which returns the answer via a callback.

    The Distributor spawns sufficient backends, and if they thrown an exception,
    it will cycle the backend but drop the query that was active during the exception.
*/

template<class Answer, class Question, class Backend> class Distributor
{
public:
  static Distributor* Create(int n=1); //!< Create a new Distributor with \param n threads
  typedef std::function<void(std::unique_ptr<Answer>&, int)> callback_t;
  virtual int question(Question&, callback_t callback) =0; //!< Submit a question to the Distributor
  virtual int getQueueSize() =0; //!< Returns length of question queue
  virtual bool isOverloaded() =0;
  virtual ~Distributor() { cerr<<__func__<<endl;}
};

template<class Answer, class Question, class Backend> class SingleThreadDistributor
    : public Distributor<Answer, Question, Backend>
{
public:
  SingleThreadDistributor(const SingleThreadDistributor&) = delete;
  void operator=(const SingleThreadDistributor&) = delete;
  SingleThreadDistributor();
  typedef std::function<void(std::unique_ptr<Answer>&, int)> callback_t;
  int question(Question&, callback_t callback) override; //!< Submit a question to the Distributor
  int getQueueSize() override {
    return 0;
  }

  bool isOverloaded() override
  {
    return false;
  }

private:
  std::unique_ptr<Backend> b{nullptr};
};

template<class Answer, class Question, class Backend> class MultiThreadDistributor
    : public Distributor<Answer, Question, Backend>
{
public:
  MultiThreadDistributor(const MultiThreadDistributor&) = delete;
  void operator=(const MultiThreadDistributor&) = delete;
  MultiThreadDistributor(int n);
  typedef std::function<void(std::unique_ptr<Answer>&, int)> callback_t;
  int question(Question&, callback_t callback) override; //!< Submit a question to the Distributor
  void distribute(int n);
  int getQueueSize() override {
    return d_queued;
  }

  struct QuestionData
  {
    QuestionData(const Question& query): Q(query)
    {
      start = Q.d_dt.udiff();
    }

    Question Q;
    callback_t callback{nullptr};
    int id{0};
    int start{0};
  };

  bool isOverloaded() override
  {
    return d_overloadQueueLength && (d_queued > d_overloadQueueLength);
  }

private:
  std::vector<pdns::channel::Sender<QuestionData>> d_senders;
  std::vector<pdns::channel::Receiver<QuestionData>> d_receivers;
  time_t d_last_started{0};
  std::atomic<unsigned int> d_queued{0};
  unsigned int d_overloadQueueLength{0};
  unsigned int d_maxQueueLength{0};
  int d_nextid{0};
  int d_num_threads{0};
};

template<class Answer, class Question, class Backend> Distributor<Answer,Question,Backend>* Distributor<Answer,Question,Backend>::Create(int n)
{
    if( n == 1 )
      return new SingleThreadDistributor<Answer,Question,Backend>();
    else
      return new MultiThreadDistributor<Answer,Question,Backend>( n );
}

template<class Answer, class Question, class Backend>SingleThreadDistributor<Answer,Question,Backend>::SingleThreadDistributor()
{
  g_log<<Logger::Error<<"Only asked for 1 backend thread - operating unthreaded"<<endl;
  try {
    b=make_unique<Backend>();
  }
  catch(const PDNSException &AE) {
    g_log<<Logger::Error<<"Distributor caught fatal exception: "<<AE.reason<<endl;
    _exit(1);
  }
  catch(const std::exception& e) {
    g_log<<Logger::Error<<"Distributor caught fatal exception: "<<e.what()<<endl;
    _exit(1);
  }
  catch(...) {
    g_log<<Logger::Error<<"Caught an unknown exception when creating backend, probably"<<endl;
    _exit(1);
  }
}

template<class Answer, class Question, class Backend>MultiThreadDistributor<Answer,Question,Backend>::MultiThreadDistributor(int numberOfThreads) :
  d_last_started(time(nullptr)), d_overloadQueueLength(::arg().asNum("overload-queue-length")), d_maxQueueLength(::arg().asNum("max-queue-length")), d_num_threads(numberOfThreads)
{
  if (numberOfThreads < 1) {
    g_log<<Logger::Error<<"Asked for fewer than 1 threads, nothing to do"<<endl;
    _exit(1);
  }

  for (int distributorIdx = 0; distributorIdx < numberOfThreads; distributorIdx++) {
    auto [sender, receiver] = pdns::channel::createObjectQueue<QuestionData>(pdns::channel::SenderBlockingMode::SenderBlocking, pdns::channel::ReceiverBlockingMode::ReceiverBlocking);
    d_senders.push_back(std::move(sender));
    d_receivers.push_back(std::move(receiver));
  }

  g_log<<Logger::Warning<<"About to create "<<numberOfThreads<<" backend threads for UDP"<<endl;

  for (int distributorIdx = 0; distributorIdx < numberOfThreads; distributorIdx++) {
    std::thread t([=](){distribute(distributorIdx);});
    t.detach();
    Utility::usleep(50000); // we've overloaded mysql in the past :-)
  }
  g_log<<Logger::Warning<<"Done launching threads, ready to distribute questions"<<endl;
}


// start of a new thread
template<class Answer, class Question, class Backend>void MultiThreadDistributor<Answer,Question,Backend>::distribute(int ournum)
{
  // this is the longest name we can use, not a typo
  setThreadName("pdns/distributo");

  try {
    auto b = make_unique<Backend>(); // this will answer our questions
    int queuetimeout = ::arg().asNum("queue-limit");
    auto& receiver = d_receivers.at(ournum);

    for (;;) {
      auto tempQD = receiver.receive();
      if (!tempQD) {
	unixDie("read");
      }
      --d_queued;
      auto questionData = std::move(*tempQD);
      std::unique_ptr<Answer> a = nullptr;
      if (queuetimeout && questionData->Q.d_dt.udiff() > queuetimeout * 1000) {
        S.inc("timedout-packets");
        continue;
      }

      bool allowRetry = true;
retry:
      // this is the only point where we interact with the backend (synchronous)
      try {
        if (!b) {
          allowRetry = false;
          b = make_unique<Backend>();
        }
        a = b->question(questionData->Q);
      }
      catch (const PDNSException &e) {
        b.reset();
        if (!allowRetry) {
          g_log<<Logger::Error<<"Backend error: "<<e.reason<<endl;
          a = questionData->Q.replyPacket();

          a->setRcode(RCode::ServFail);
          S.inc("servfail-packets");
          S.ringAccount("servfail-queries", questionData->Q.qdomain, questionData->Q.qtype);
        } else {
          g_log<<Logger::Notice<<"Backend error (retry once): "<<e.reason<<endl;
          goto retry;
        }
      }
      catch (...) {
        b.reset();
        if (!allowRetry) {
          g_log<<Logger::Error<<"Caught unknown exception in Distributor thread "<<std::this_thread::get_id()<<endl;
          a = questionData->Q.replyPacket();

          a->setRcode(RCode::ServFail);
          S.inc("servfail-packets");
          S.ringAccount("servfail-queries", questionData->Q.qdomain, questionData->Q.qtype);
        } else {
          g_log<<Logger::Warning<<"Caught unknown exception in Distributor thread "<<std::this_thread::get_id()<<" (retry once)"<<endl;
          goto retry;
        }
      }

      questionData->callback(a, questionData->start);
#ifdef ENABLE_GSS_TSIG
      if (g_doGssTSIG && a != nullptr) {
        questionData->Q.cleanupGSS(a->d.rcode);
      }
#endif
      questionData.reset();
    }

    b.reset();
  }
  catch (const PDNSException &AE) {
    g_log<<Logger::Error<<"Distributor caught fatal exception: "<<AE.reason<<endl;
    _exit(1);
  }
  catch (const std::exception& e) {
    g_log<<Logger::Error<<"Distributor caught fatal exception: "<<e.what()<<endl;
    _exit(1);
  }
  catch (...) {
    g_log<<Logger::Error<<"Caught an unknown exception when creating backend, probably"<<endl;
    _exit(1);
  }
}

template<class Answer, class Question, class Backend>int SingleThreadDistributor<Answer,Question,Backend>::question(Question& q, callback_t callback)
{
  int start = q.d_dt.udiff();
  std::unique_ptr<Answer> a = nullptr;
  bool allowRetry=true;
retry:
  try {
    if (!b) {
      allowRetry=false;
      b=make_unique<Backend>();
    }
    a=b->question(q); // a can be NULL!
  }
  catch(const PDNSException &e) {
    b.reset();
    if (!allowRetry) {
      g_log<<Logger::Error<<"Backend error: "<<e.reason<<endl;
      a=q.replyPacket();

      a->setRcode(RCode::ServFail);
      S.inc("servfail-packets");
      S.ringAccount("servfail-queries", q.qdomain, q.qtype);
    } else {
      g_log<<Logger::Notice<<"Backend error (retry once): "<<e.reason<<endl;
      goto retry;
    }
  }
  catch(...) {
    b.reset();
    if (!allowRetry) {
      g_log<<Logger::Error<<"Caught unknown exception in Distributor thread "<<std::this_thread::get_id()<<endl;
      a=q.replyPacket();

      a->setRcode(RCode::ServFail);
      S.inc("servfail-packets");
      S.ringAccount("servfail-queries", q.qdomain, q.qtype);
    } else {
      g_log<<Logger::Warning<<"Caught unknown exception in Distributor thread "<<std::this_thread::get_id()<<" (retry once)"<<endl;
      goto retry;
    }
  }
  callback(a, start);
#ifdef ENABLE_GSS_TSIG
  if (g_doGssTSIG && a != nullptr) {
    q.cleanupGSS(a->d.rcode);
  }
#endif
  return 0;
}

struct DistributorFatal{};

template<class Answer, class Question, class Backend>int MultiThreadDistributor<Answer,Question,Backend>::question(Question& q, callback_t callback)
{
  // this is passed to other process over pipe and released there
  auto questionData = std::make_unique<QuestionData>(q);
  auto ret = questionData->id = d_nextid++; // might be deleted after write!
  questionData->callback = callback;

  ++d_queued;
  if (!d_senders.at(questionData->id % d_senders.size()).send(std::move(questionData))) {
    --d_queued;
    questionData.reset();
    unixDie("write");
  }

  if (d_queued > d_maxQueueLength) {
    g_log<<Logger::Error<< d_queued <<" questions waiting for database/backend attention. Limit is "<<::arg().asNum("max-queue-length")<<", respawning"<<endl;
    // this will leak the entire contents of all pipes, nothing will be freed. Respawn when this happens!
    throw DistributorFatal();
  }

  return ret;
}
