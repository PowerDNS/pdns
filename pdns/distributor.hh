/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2015  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef DISTRIBUTOR_HH
#define DISTRIBUTOR_HH

#include <string>
#include <deque>
#include <queue>
#include <vector>
#include <pthread.h>
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
  static Distributor *Create(int n=1); //!< Create a new Distributor with \param n threads
  typedef std::function<void(Answer*)> callback_t;
  virtual int question(Question *, callback_t callback) =0; //!< Submit a question to the Distributor
  virtual int getQueueSize() =0; //!< Returns length of question queue
  virtual bool isOverloaded() =0;
};

template<class Answer, class Question, class Backend> class SingleThreadDistributor
    : public Distributor<Answer, Question, Backend>
{
public:
  SingleThreadDistributor();
  typedef std::function<void(Answer*)> callback_t;
  int question(Question *, callback_t callback) override; //!< Submit a question to the Distributor
  int getQueueSize() {
    return 0;
  }

  bool isOverloaded()
  {
    return false;
  }

  ~SingleThreadDistributor() {
    if (b) delete b;
  }
private:
  Backend *b{0};
};

template<class Answer, class Question, class Backend> class MultiThreadDistributor
    : public Distributor<Answer, Question, Backend>
{
public:
  MultiThreadDistributor(int n);
  typedef std::function<void(Answer*)> callback_t;
  int question(Question *, callback_t callback) override; //!< Submit a question to the Distributor
  static void* makeThread(void *); //!< helper function to create our n threads
  int getQueueSize() override {
    return d_queued;
  }

  struct QuestionData
  {
    Question *Q;
    callback_t callback;
    int id;
  };

  bool isOverloaded() override
  {
    return d_overloaded;
  }
  
private:
  bool d_overloaded;
  int nextid;
  time_t d_last_started;
  int d_num_threads;
  std::atomic<unsigned int> d_queued{0}, d_running{0};
  std::vector<std::pair<int,int>> d_pipes;
};

//template<class Answer, class Question, class Backend>::nextid;
template<class Answer, class Question, class Backend>Distributor<Answer,Question,Backend>* Distributor<Answer,Question,Backend>::Create(int n)
{
    if( n == 1 )
        return new SingleThreadDistributor<Answer,Question,Backend>();
    else
        return new MultiThreadDistributor<Answer,Question,Backend>( n );
}

template<class Answer, class Question, class Backend>SingleThreadDistributor<Answer,Question,Backend>::SingleThreadDistributor()
{
  L<<Logger::Error<<"Only asked for 1 backend thread - operating unthreaded"<<endl;
  b=new Backend;
}

template<class Answer, class Question, class Backend>MultiThreadDistributor<Answer,Question,Backend>::MultiThreadDistributor(int n)
{
  d_num_threads=n;
  d_overloaded = false;

  nextid=0;
  d_last_started=time(0);

  pthread_t tid;
  

  for(int i=0; i < n; ++i) {
    int fds[2];
    if(pipe(fds) < 0)
      unixDie("Creating pipe");
    d_pipes.push_back({fds[0],fds[1]});
  }
  
  L<<Logger::Warning<<"About to create "<<n<<" backend threads for UDP"<<endl;
  for(int i=0;i<n;i++) {
    pthread_create(&tid,0,&makeThread,static_cast<void *>(this));
    Utility::usleep(50000); // we've overloaded mysql in the past :-)
  }
  L<<Logger::Warning<<"Done launching threads, ready to distribute questions"<<endl;
}


// start of a new thread
template<class Answer, class Question, class Backend>void *MultiThreadDistributor<Answer,Question,Backend>::makeThread(void *p)
{
  pthread_detach(pthread_self());
  MultiThreadDistributor *us=static_cast<MultiThreadDistributor *>(p);
  int ournum=us->d_running++;

  try {
    Backend *b=new Backend(); // this will answer our questions
    int queuetimeout=::arg().asNum("queue-limit"); 

    for(;;) {
    
      QuestionData* QD;
      if(read(us->d_pipes[ournum].first, &QD, sizeof(QD)) != sizeof(QD))
	unixDie("read");
      --us->d_queued;
      Answer *a; 

      if(queuetimeout && QD->Q->d_dt.udiff()>queuetimeout*1000) {
        delete QD->Q;
	delete QD;
        S.inc("timedout-packets");
        continue;
      }        
      // this is the only point where we interact with the backend (synchronous)
      try {
        a=b->question(QD->Q); 
	delete QD->Q;
      }
      catch(const PDNSException &e) {
        L<<Logger::Error<<"Backend error: "<<e.reason<<endl;
	delete b;
	b=new Backend();
        a=QD->Q->replyPacket();

        a->setRcode(RCode::ServFail);
        S.inc("servfail-packets");
        S.ringAccount("servfail-queries",QD->Q->qdomain.toString());

	delete QD->Q;
      }
      catch(...) {
        L<<Logger::Error<<"Caught unknown exception in Distributor thread "<<(long)pthread_self()<<endl;
	delete b;
	b=new Backend();
        a=QD->Q->replyPacket();
	
        a->setRcode(RCode::ServFail);
        S.inc("servfail-packets");
        S.ringAccount("servfail-queries",QD->Q->qdomain.toString());
	delete QD->Q;
      }

      QD->callback(a);
      delete QD;
    }
    
    delete b;
  }
  catch(const PDNSException &AE) {
    L<<Logger::Error<<"Distributor caught fatal exception: "<<AE.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Caught an unknown exception when creating backend, probably"<<endl;
  }
  return 0;
}

template<class Answer, class Question, class Backend>int SingleThreadDistributor<Answer,Question,Backend>::question(Question* q, callback_t callback)
{
  Answer *a;
  try {
    a=b->question(q); // a can be NULL!
  }
  catch(const PDNSException &e) {
    L<<Logger::Error<<"Backend error: "<<e.reason<<endl;
    delete b;
    b=new Backend;
    a=q->replyPacket();
    a->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",q->qdomain.toString());
  }
  catch(...) {
    L<<Logger::Error<<"Caught unknown exception in Distributor thread "<<(unsigned long)pthread_self()<<endl;
    delete b;
    b=new Backend;
    a=q->replyPacket();
    a->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",q->qdomain.toString());
  }
  callback(a);
  return 0;
}

struct DistributorFatal{};

template<class Answer, class Question, class Backend>int MultiThreadDistributor<Answer,Question,Backend>::question(Question* q, callback_t callback)
{
  q=new Question(*q);

  auto QD=new QuestionData();
  QD->Q=q;
  auto ret = QD->id = nextid++; // might be deleted after write!
  QD->callback=callback;
  
  if(write(d_pipes[QD->id % d_pipes.size()].second, &QD, sizeof(QD)) != sizeof(QD))
    unixDie("write");

  d_queued++;
  
  static unsigned int overloadQueueLength=::arg().asNum("overload-queue-length");
  static unsigned int maxQueueLength=::arg().asNum("max-queue-length");

  if(overloadQueueLength) 
    d_overloaded= d_queued > overloadQueueLength;

  if(d_queued > maxQueueLength) {
    L<<Logger::Error<< d_queued <<" questions waiting for database/backend attention. Limit is "<<::arg().asNum("max-queue-length")<<", respawning"<<endl;
    // this will leak the entire contents of all pipes, nothing will be freed. Respawn when this happens!
    throw DistributorFatal();
  }
   
  return ret;
}

#endif // DISTRIBUTOR_HH

