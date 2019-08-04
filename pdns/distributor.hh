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
#ifndef DISTRIBUTOR_HH
#define DISTRIBUTOR_HH

#include <string>
#include <deque>
#include <queue>
#include <vector>
#include <pthread.h>
#include "threadname.hh"
#include <unistd.h>
#include "logger.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "pdnsexception.hh"
#include "arguments.hh"
#include <atomic>
#include "statbag.hh"

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
  typedef std::function<void(std::unique_ptr<Answer>&)> callback_t;
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
  typedef std::function<void(std::unique_ptr<Answer>&)> callback_t;
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
  typedef std::function<void(std::unique_ptr<Answer>&)> callback_t;
  int question(Question&, callback_t callback) override; //!< Submit a question to the Distributor
  static void* makeThread(void *); //!< helper function to create our n threads
  int getQueueSize() override {
    return d_queued;
  }

  struct QuestionData
  {
    QuestionData(const Question& query): Q(query)
    {
    }

    Question Q;
    callback_t callback;
    int id;
  };

  bool isOverloaded() override
  {
    return d_overloadQueueLength && (d_queued > d_overloadQueueLength);
  }

private:
  int nextid;
  time_t d_last_started;
  unsigned int d_overloadQueueLength, d_maxQueueLength;
  int d_num_threads;
  std::atomic<unsigned int> d_queued{0}, d_running{0};
  std::vector<std::pair<int,int>> d_pipes;
};

//template<class Answer, class Question, class Backend>::nextid;
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
  catch(...) {
    g_log<<Logger::Error<<"Caught an unknown exception when creating backend, probably"<<endl;
    _exit(1);
  }
}

template<class Answer, class Question, class Backend>MultiThreadDistributor<Answer,Question,Backend>::MultiThreadDistributor(int n)
{
  d_num_threads=n;
  d_overloadQueueLength=::arg().asNum("overload-queue-length");
  d_maxQueueLength=::arg().asNum("max-queue-length");
  nextid=0;
  d_last_started=time(0);

  pthread_t tid;
  

  for(int i=0; i < n; ++i) {
    int fds[2];
    if(pipe(fds) < 0)
      unixDie("Creating pipe");
    d_pipes.push_back({fds[0],fds[1]});
  }
  
  if (n<1) {
    g_log<<Logger::Error<<"Asked for fewer than 1 threads, nothing to do"<<endl;
    _exit(1);
  }

  g_log<<Logger::Warning<<"About to create "<<n<<" backend threads for UDP"<<endl;
  for(int i=0;i<n;i++) {
    pthread_create(&tid,0,&makeThread,static_cast<void *>(this));
    Utility::usleep(50000); // we've overloaded mysql in the past :-)
  }
  g_log<<Logger::Warning<<"Done launching threads, ready to distribute questions"<<endl;
}


// start of a new thread
template<class Answer, class Question, class Backend>void *MultiThreadDistributor<Answer,Question,Backend>::makeThread(void *p)
{
  setThreadName("pdns/distributo");
  pthread_detach(pthread_self());
  MultiThreadDistributor *us=static_cast<MultiThreadDistributor *>(p);
  int ournum=us->d_running++;

  try {
    std::unique_ptr<Backend> b= make_unique<Backend>(); // this will answer our questions
    int queuetimeout=::arg().asNum("queue-limit"); 

    for(;;) {
    
      QuestionData* tempQD = nullptr;
      if(read(us->d_pipes[ournum].first, &tempQD, sizeof(tempQD)) != sizeof(tempQD))
	unixDie("read");
      --us->d_queued;
      std::unique_ptr<QuestionData> QD = std::unique_ptr<QuestionData>(tempQD);
      tempQD = nullptr;
      std::unique_ptr<Answer> a = nullptr;

      if(queuetimeout && QD->Q.d_dt.udiff()>queuetimeout*1000) {
        S.inc("timedout-packets");
        continue;
      }        

      bool allowRetry=true;
retry:
      // this is the only point where we interact with the backend (synchronous)
      try {
        if (!b) {
          allowRetry=false;
          b=make_unique<Backend>();
        }
        a=b->question(QD->Q);
      }
      catch(const PDNSException &e) {
        b.reset();
        if (!allowRetry) {
          g_log<<Logger::Error<<"Backend error: "<<e.reason<<endl;
          a=QD->Q.replyPacket();

          a->setRcode(RCode::ServFail);
          S.inc("servfail-packets");
          S.ringAccount("servfail-queries", QD->Q.qdomain, QD->Q.qtype);
        } else {
          g_log<<Logger::Notice<<"Backend error (retry once): "<<e.reason<<endl;
          goto retry;
        }
      }
      catch(...) {
        b.reset();
        if (!allowRetry) {
          g_log<<Logger::Error<<"Caught unknown exception in Distributor thread "<<(long)pthread_self()<<endl;
          a=QD->Q.replyPacket();

          a->setRcode(RCode::ServFail);
          S.inc("servfail-packets");
          S.ringAccount("servfail-queries", QD->Q.qdomain, QD->Q.qtype);
        } else {
          g_log<<Logger::Warning<<"Caught unknown exception in Distributor thread "<<(long)pthread_self()<<" (retry once)"<<endl;
          goto retry;
        }
      }

      QD->callback(a);
      QD.reset();
    }

    b.reset();
  }
  catch(const PDNSException &AE) {
    g_log<<Logger::Error<<"Distributor caught fatal exception: "<<AE.reason<<endl;
    _exit(1);
  }
  catch(...) {
    g_log<<Logger::Error<<"Caught an unknown exception when creating backend, probably"<<endl;
    _exit(1);
  }
  return 0;
}

template<class Answer, class Question, class Backend>int SingleThreadDistributor<Answer,Question,Backend>::question(Question& q, callback_t callback)
{
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
      g_log<<Logger::Error<<"Caught unknown exception in Distributor thread "<<(unsigned long)pthread_self()<<endl;
      a=q.replyPacket();

      a->setRcode(RCode::ServFail);
      S.inc("servfail-packets");
      S.ringAccount("servfail-queries", q.qdomain, q.qtype);
    } else {
      g_log<<Logger::Warning<<"Caught unknown exception in Distributor thread "<<(unsigned long)pthread_self()<<" (retry once)"<<endl;
      goto retry;
    }
  }
  callback(a);
  return 0;
}

struct DistributorFatal{};

template<class Answer, class Question, class Backend>int MultiThreadDistributor<Answer,Question,Backend>::question(Question& q, callback_t callback)
{
  // this is passed to other process over pipe and released there
  auto QD=new QuestionData(q);
  auto ret = QD->id = nextid++; // might be deleted after write!
  QD->callback=callback;

  ++d_queued;
  if(write(d_pipes[QD->id % d_pipes.size()].second, &QD, sizeof(QD)) != sizeof(QD)) {
    --d_queued;
    delete QD;
    unixDie("write");
  }

  if(d_queued > d_maxQueueLength) {
    g_log<<Logger::Error<< d_queued <<" questions waiting for database/backend attention. Limit is "<<::arg().asNum("max-queue-length")<<", respawning"<<endl;
    // this will leak the entire contents of all pipes, nothing will be freed. Respawn when this happens!
    throw DistributorFatal();
  }

  return ret;
}

#endif // DISTRIBUTOR_HH

