/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef DISTRIBUTOR_HH
#define DISTRIBUTOR_HH


#include <string>
#include <deque>
#include <queue>
#include <vector>
#include <pthread.h>
#include <semaphore.h>

#ifndef WIN32
# include <unistd.h>
#endif // WIN32

#include "logger.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "ahuexception.hh"


/** the Distributor template class enables you to multithread slow question/answer 
    processes. 
    
    Questions are posed to the Distributor, which can either hand back the answer,
    or give it directly to a callback. Only the latter mode of operation is used in 
    PowerDNS. 

    The Distributor takes care that there are enough Backends alive at any one
    time and will try to spawn additional ones should they die.

    The Backend needs to count the number of living instances and supply this number to
    the Distributor using its numBackends() method. This is silly.

    If an exception escapes a Backend, the distributor retires it.
*/
template<class Answer, class Question, class Backend> class Distributor
{
public:
  Distributor(int n=10); //!< Create a new Distributor with \param n threads
  struct AnswerData
  {
    Answer *A;
    time_t created;
  };  
  int question(Question *, void (*)(const AnswerData &)=0); //!< Submit a question to the Distributor
  Answer *answer(void); //!< Wait for any answer from the Distributor
  Answer *wait(Question *); //!< wait for an answer to a specific question
  int timeoutWait(int id, Answer *, int); //!< wait for a specific answer, with timeout
  static void* makeThread(void *); //!< helper function to create our n threads
  void getQueueSizes(int &questions, int &answers); //!< Returns length of question queue


  //! This function can run in a separate thread to output statistics on the queues
  static void* doStats(void *p)
  {
    Distributor *us=static_cast<Distributor *>(p);
    for(;;)
      {
	sleep(1);
	int qcount, acount;

	us->numquestions.getvalue( &qcount );
	us->numanswers.getvalue( &acount );

	L <<"queued questions: "<<qcount<<", pending answers: "<<acount<<endl;
      }
  }

  int getNumBusy()
  {
    return d_num_threads-d_idle_threads;
  }




  struct QuestionData
  {
    Question *Q;
    time_t created;
    void (*callback)(const AnswerData &);
    int id;
  };


  typedef pair<QuestionData, AnswerData> tuple_t;
  
private:
  std::queue<QuestionData> questions;
  pthread_mutex_t q_lock;

  
  deque<tuple_t> answers;
  pthread_mutex_t a_lock;

  Semaphore numquestions;
  Semaphore numanswers;

  pthread_mutex_t to_mut;
  pthread_cond_t to_cond;

  int nextid;
  time_t d_last_started;
  int d_num_threads;
  int d_idle_threads;
  Backend *b;
};


//template<class Answer, class Question, class Backend>::nextid;

template<class Answer, class Question, class Backend>Distributor<Answer,Question,Backend>::Distributor(int n)
{
  b=0;
  d_idle_threads=0;
  d_last_started=time(0);
//  sem_init(&numquestions,0,0);
  pthread_mutex_init(&q_lock,0);

//  sem_init(&numanswers,0,0);
  pthread_mutex_init(&a_lock,0);

  pthread_mutex_init(&to_mut,0);
  pthread_cond_init(&to_cond,0);

  pthread_t tid;
  
  d_num_threads=n;

  L<<Logger::Warning<<"About to create "<<n<<" backend threads"<<endl;

  for(int i=0;i<n;i++) {
    pthread_create(&tid,0,&makeThread,static_cast<void *>(this));
    Utility::usleep(50000); // we've overloaded mysql in the past :-)
  }

  L<<"Done launching threads, ready to distribute questions"<<endl;
}

// start of a new thread
template<class Answer, class Question, class Backend>void *Distributor<Answer,Question,Backend>::makeThread(void *p)
{
  try {
    Backend *b=new Backend(); // this will answer our questions
    Distributor *us=static_cast<Distributor *>(p);
    int qcount;

    // this is so gross
#ifndef SMTPREDIR 
    int queuetimeout=arg().asNum("queue-limit"); 
#endif 
    // ick ick ick!

    for(;;) {
      us->d_idle_threads++;

      us->numquestions.getValue( &qcount );

      us->numquestions.wait();

      us->d_idle_threads--;
      pthread_mutex_lock(&us->q_lock);

      QuestionData QD=us->questions.front();

      Question *q=QD.Q;
      
      us->questions.pop();
      
      pthread_mutex_unlock(&us->q_lock);
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
      catch(const AhuException &e) {
        L<<Logger::Error<<"Backend error: "<<e.reason<<endl;
	delete b;
        return 0;
      }
      catch(...) {
        L<<Logger::Error<<Logger::NTLog<<"Caught unknown exception in Distributor thread "<<(unsigned long)pthread_self()<<endl;
	delete b;
        return 0;
      }

      AnswerData AD;
      AD.A=a;
      AD.created=time(0);
      tuple_t tuple(QD,AD);

      if(QD.callback) {
	QD.callback(AD);
      }
      else {
	pthread_mutex_lock(&us->a_lock);

	us->answers.push_back(tuple);
	pthread_mutex_unlock(&us->a_lock);
      
	//	  L<<"We have an answer to send! Trying to get to to_mut lock"<<endl;
	pthread_mutex_lock(&us->to_mut); 
	// L<<"Yes, we got the lock, we can transmit! First we post"<<endl;
	us->numanswers.post();
	// L<<"And now we broadcast!"<<endl;
	pthread_cond_broadcast(&us->to_cond); // for timeoutWait(); 
	pthread_mutex_unlock(&us->to_mut);
      }
    }
    
    delete b;
  }
  catch(const AhuException &AE) {
    L<<Logger::Error<<Logger::NTLog<<"Distributor caught fatal exception: "<<AE.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<Logger::NTLog<<"Caught an unknown exception when creating backend, probably"<<endl;
  }
  return 0;
}

template<class Answer, class Question, class Backend>int Distributor<Answer,Question,Backend>::question(Question* q, void (*callback)(const AnswerData &))
{
  if(d_num_threads==1 && callback) {  // short circuit
    if(!b) {
      L<<Logger::Error<<"Engaging bypass - now operating unthreaded"<<endl;
      b=new Backend;
    }
    Answer *a;

    a=b->question(q);

    AnswerData AD;
    AD.A=a;
    AD.created=time(0);
    callback(AD); 
    return 0;
  }
  else {
    q=new Question(*q);
  }

  DLOG(L<<"Distributor has "<<Backend::numRunning()<<" threads available"<<endl);
  if(Backend::numRunning()<d_num_threads && time(0)-d_last_started>5) { // add one
    d_last_started=time(0);
    L<<"Distributor misses a thread ("<<Backend::numRunning()<<"<"<<d_num_threads<<"), spawning new one"<<endl;
    pthread_t tid;
    pthread_create(&tid,0,&makeThread,static_cast<void *>(this));
  }

  pthread_mutex_lock(&q_lock);
  QuestionData QD;
  QD.Q=q;
  QD.id=nextid++;
  QD.callback=callback;
  questions.push(QD);
  pthread_mutex_unlock(&q_lock);

  numquestions.post();

  if(!(nextid%50)) {
    int val;
    numquestions.getValue( &val );
    if(val>arg().asNum("max-queue-length")) {
      L<<Logger::Error<<val<<" questions waiting for database attention. Limit is "<<arg().asNum("max-queue-length")<<", respawning"<<endl;
      exit(1);
    }
  }

  return QD.id;
}

template<class Answer, class Question,class Backend>Answer* Distributor<Answer,Question,Backend>::answer()
{
  numanswers.wait();
  tuple_t tuple;

  pthread_mutex_lock(&a_lock);
  tuple=answers.front();
  answers.pop_front();
  pthread_mutex_unlock(&a_lock);
  return tuple.second.A;
}

//! Wait synchronously for the answer of the question just asked. For this to work, no answer() functions must be called
template<class Answer, class Question,class Backend>Answer* Distributor<Answer,Question,Backend>::wait(Question *q)
{
  for(;;)
    {
      numanswers.wait();
      pthread_mutex_lock(&a_lock);
      
      // search if the answer is there
      tuple_t tuple=answers.front();
      if(tuple.first==q)
	{
	  answers.pop_front();
	  pthread_mutex_unlock(&a_lock);
	  return tuple.second.A;
	}
      // if not, loop again
      pthread_mutex_unlock(&a_lock);
      numanswers.post();
    }
  // FIXME: write this
}

template<class Answer, class Question,class Backend>void Distributor<Answer,Question,Backend>::getQueueSizes(int &questions, int &answers)
{
  numquestions.getValue( &questions );
  numanswers.getValue( &answers );
}

//! Wait synchronously for the answer of the question just asked. For this to work, no answer() functions must be called
template<class Answer, class Question,class Backend>int Distributor<Answer,Question,Backend>::timeoutWait(int id, Answer *a, int timeout)
{
  struct timeval now;
  struct timespec then;

  Utility::gettimeofday(&now,0);

  then.tv_sec=now.tv_sec+timeout;  
  then.tv_nsec=150*1000000+now.tv_usec*1000; // 150ms

  int rc;

  //  L<<"About to acquire to_mut - new broadcasts will then be corked"<<endl;
  pthread_mutex_lock(&to_mut);  // start the lock to prevent races

  for(;;)
    {
      //      L<<"Acquired the to_mut lock - checking to see if there are already answers"<<endl;

      int val;
      rc=numanswers.getvalue( &val); // are there answers?
      //      L<<"Now "<<val<<" answers according to the semaphore"<<endl;

      if(val)
	{
	  DLOG(L<<"There are some answers! Is the one we want among them?"<<endl);
	  DLOG(L<<"numanswers: "<<val<<", rc="<<rc<<", errno="<<errno<<endl);

	  pthread_mutex_lock(&a_lock);
	  
	  DLOG(L<<"deque contains: "<<answers.size()<<endl);
	  // search if the answer is there
	  
	  bool found=false;
	  int rc;
	  
	  for(typename deque<tuple_t>::iterator tuple=answers.begin();
	      tuple!=answers.end();
	      tuple++)
	    {
	      if(!found && tuple->first.id==id)
		{
		  numanswers.wait(); // remove from the semaphore
		  DLOG(L<<"found the answer tuple ("<<tuple->first.id<<") - may be empty answer"<<endl);
		  
		  found=true;
		  
		  if(!tuple->second.A)
		    rc=-1;
		  else
		    {
		      *a=*tuple->second.A;
		      rc=0;
		    }
		  
		  answers.erase(tuple);
		  tuple=answers.begin(); // restart
		  if(tuple==answers.end())break;
		  
		}
	      else  // an answer, but not the right one
		{
		  if(time(0)-tuple->second.created>5) // delete after 5 seconds
		    {
		      L<<"Deleted unclaimed answer "<<tuple->first.id<<" due to age"<<endl;
		      answers.erase(tuple);
		      tuple=answers.begin(); // restart
		      if(tuple==answers.end())break;
		      numanswers.wait();
		    }
		}
	    }
	  pthread_mutex_unlock(&a_lock);

	  if(!found)
	    L<<"Right answer was NOT found - we should now sleep and recheck whenever there are new answers"<<endl;
	  else 
	    {
	      pthread_mutex_unlock(&to_mut);
	      return 0;
	    }
	}
      else
	L<<"No answers!"<<endl;


      DLOG(L<<"starting wait on condition, to see if there are new answers"<<endl);

      // this first lets go of the to_mut lock, which will 'uncork' the pending pthread_cond_broadcasts
      rc=pthread_cond_timedwait(&to_cond, &to_mut, &then);
      // and then it atomically reacquires the lock

      if(rc==ETIMEDOUT)
	{
	  L<<Logger::Error<<"Timeout waiting for data"<<endl;
	  pthread_mutex_unlock(&to_mut);
	  return -ETIMEDOUT;
	}
      L<<"We received a broadcast that there is new data, checking"<<endl;

    }

  return -1; // timeout or whatever
  // FIXME: write this
}


#endif // DISTRIBUTOR_HH

