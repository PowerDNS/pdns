/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

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
#include <semaphore.h>
#include <unistd.h>
#include "logger.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "pdnsexception.hh"
#include "arguments.hh"
#include "statbag.hh"

extern StatBag S;

/** the Distributor template class enables you to multithread slow question/answer 
    processes. 
    
    Questions are posed to the Distributor, which returns the answer via a callback.

    The Distributor takes care that there are enough Backends alive at any one
    time and will try to spawn additional ones should they die.

    The Backend needs to count the number of living instances and supply this number to
    the Distributor using its numBackends() method. This is silly.

    If an exception escapes a Backend, the distributor retires it.
*/
template<class Answer>struct AnswerData
{
  Answer *A;
};

template<class Answer, class Question, class Backend> class Distributor
{
public:
  static Distributor *Create(int n=1); //!< Create a new Distributor with \param n threads

  virtual void cleanup();
  virtual int question(Question *, void (*)(const AnswerData<Answer> &)) {return 0;}; //!< Submit a question to the Distributor
  virtual void getQueueSizes(int &questions, int &answers) {}; //!< Returns length of question queue

  virtual int getNumBusy() {return 0;};

  virtual bool isOverloaded() {return false;};

private:
};

template<class Answer, class Question, class Backend> class SingleThreadDistributor
    : public Distributor<Answer, Question, Backend>
{
public:
  SingleThreadDistributor();
  int question(Question *, void (*)(const AnswerData<Answer> &)); //!< Submit a question to the Distributor
  void getQueueSizes(int &questions, int &answers) {
    questions = 0;
    answers = 0;
  }

  int getNumBusy()
  {
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
  Backend *b;
};

template<class Answer, class Question, class Backend> class MultiThreadDistributor
    : public Distributor<Answer, Question, Backend>
{
public:
  MultiThreadDistributor(int n=1);
  int question(Question *, void (*)(const AnswerData<Answer> &)); //!< Submit a question to the Distributor
  static void* makeThread(void *); //!< helper function to create our n threads
  void getQueueSizes(int &questions, int &answers) {
      numquestions.getValue( &questions );
      answers = 0;
  }

  int getNumBusy()
  {
    return d_num_threads-d_idle_threads;
  }

  struct QuestionData
  {
    Question *Q;
    void (*callback)(const AnswerData<Answer> &);
    int id;
  };

  bool isOverloaded()
  {
    return d_overloaded;
  }
  
private:
  bool d_overloaded;
  std::queue<QuestionData> questions;
  pthread_mutex_t q_lock;

  Semaphore numquestions;

  pthread_mutex_t to_mut;
  pthread_cond_t to_cond;

  int nextid;
  time_t d_last_started;
  int d_num_threads;
  AtomicCounter d_idle_threads;
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
  // d_idle_threads=0;
  d_last_started=time(0);
//  sem_init(&numquestions,0,0);
  pthread_mutex_init(&q_lock,0);

  pthread_mutex_init(&to_mut,0);
  pthread_cond_init(&to_cond,0);

  pthread_t tid;
  
  L<<Logger::Warning<<"About to create "<<n<<" backend threads for UDP"<<endl;
  for(int i=0;i<n;i++) {
    pthread_create(&tid,0,&makeThread,static_cast<void *>(this));
    Utility::usleep(50000); // we've overloaded mysql in the past :-)
  }
  L<<Logger::Warning<<"Done launching threads, ready to distribute questions"<<endl;
}

template<class Answer, class Question, class Backend>void Distributor<Answer,Question,Backend>::cleanup()
{
    L<<Logger::Error<< "Cleaning up distributor" <<endl;
}

// start of a new thread
template<class Answer, class Question, class Backend>void *MultiThreadDistributor<Answer,Question,Backend>::makeThread(void *p)
{
  pthread_detach(pthread_self());
  try {
    Backend *b=new Backend(); // this will answer our questions
    MultiThreadDistributor *us=static_cast<MultiThreadDistributor *>(p);
    int qcount;

    // this is so gross
#ifndef SMTPREDIR 
    int queuetimeout=::arg().asNum("queue-limit"); 
#endif 
    // ick ick ick!
    static int overloadQueueLength=::arg().asNum("overload-queue-length");
    for(;;) {
      ++(us->d_idle_threads);

      us->numquestions.getValue( &qcount );

      us->numquestions.wait();

      --(us->d_idle_threads);
      pthread_mutex_lock(&us->q_lock);

      QuestionData QD=us->questions.front();

      us->questions.pop();
      pthread_mutex_unlock(&us->q_lock);

      Question *q=QD.Q;
      

      if(us->d_overloaded && qcount <= overloadQueueLength/10) {
        us->d_overloaded=false;
      }
      
      Answer *a; 

#ifndef SMTPREDIR
      if(queuetimeout && q->d_dt.udiff()>queuetimeout*1000) {
        delete q;
        S.inc("timedout-packets");
        continue;
      }        
#endif  
      // this is the only point where we interact with the backend (synchronous)
      try {
        a=b->question(q); // a can be NULL!
        delete q;
      }
      catch(const PDNSException &e) {
        L<<Logger::Error<<"Backend error: "<<e.reason<<endl;
        a=q->replyPacket();
        a->setRcode(RCode::ServFail);
        S.inc("servfail-packets");
        S.ringAccount("servfail-queries",q->qdomain);
      }
      catch(...) {
        L<<Logger::Error<<Logger::NTLog<<"Caught unknown exception in Distributor thread "<<(unsigned long)pthread_self()<<endl;
        a=q->replyPacket();
        a->setRcode(RCode::ServFail);
        S.inc("servfail-packets");
        S.ringAccount("servfail-queries",q->qdomain);
      }

      AnswerData<Answer> AD;
      AD.A=a;

      QD.callback(AD);
    }
    
    delete b;
  }
  catch(const PDNSException &AE) {
    L<<Logger::Error<<Logger::NTLog<<"Distributor caught fatal exception: "<<AE.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<Logger::NTLog<<"Caught an unknown exception when creating backend, probably"<<endl;
  }
  return 0;
}

template<class Answer, class Question, class Backend>int SingleThreadDistributor<Answer,Question,Backend>::question(Question* q, void (*callback)(const AnswerData<Answer> &))
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
    S.ringAccount("servfail-queries",q->qdomain);
  }
  catch(...) {
    L<<Logger::Error<<Logger::NTLog<<"Caught unknown exception in Distributor thread "<<(unsigned long)pthread_self()<<endl;
    delete b;
    b=new Backend;
    a=q->replyPacket();
    a->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",q->qdomain);
  }
  AnswerData<Answer> AD;
  AD.A=a;
  callback(AD);
  return 0;
}

template<class Answer, class Question, class Backend>int MultiThreadDistributor<Answer,Question,Backend>::question(Question* q, void (*callback)(const AnswerData<Answer> &))
{
  // XXX assert callback
  q=new Question(*q);

  DLOG(L<<"Distributor has "<<Backend::numRunning()<<" threads available"<<endl);

  /* the line below is a bit difficult.
     What happens is that we have a goal for the number of running distributor threads. Furthermore, other
     parts of PowerDNS also start backends, which get included in this count.

     If less than two threads now die, no new ones will be spawned.

     The solutionis to add '+2' below, but it is not a pretty solution. Better solution is
     to only account the number of threads within the Distributor, and not in the backend.

     XXX FIXME 
  */

  if(Backend::numRunning() < d_num_threads+2 && time(0)-d_last_started>5) { 
    d_last_started=time(0);
    L<<"Distributor misses a thread ("<<Backend::numRunning()<<"<"<<d_num_threads + 2<<"), spawning new one"<<endl;
    pthread_t tid;
    pthread_create(&tid,0,&makeThread,static_cast<void *>(this));
  }

  QuestionData QD;
  QD.Q=q;
  QD.id=nextid++;
  QD.callback=callback;

  pthread_mutex_lock(&q_lock);
  questions.push(QD);
  pthread_mutex_unlock(&q_lock);

  numquestions.post();
  
  static int overloadQueueLength=::arg().asNum("overload-queue-length");

  if(!(nextid%50)) {
    int val;
    numquestions.getValue( &val );
    
    if(!d_overloaded)
      d_overloaded = overloadQueueLength && (val > overloadQueueLength);

    if(val>::arg().asNum("max-queue-length")) {
      L<<Logger::Error<<val<<" questions waiting for database attention. Limit is "<<::arg().asNum("max-queue-length")<<", respawning"<<endl;
      _exit(1);
    }

  }

  return QD.id;
}

#endif // DISTRIBUTOR_HH

