#include <vector>
#include <deque>
#include <iostream>
#include <boost/foreach.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/format.hpp>
#include <sys/time.h>
#include <time.h>
#include "iputils.hh"
#include "statbag.hh"
#include <sys/socket.h>

using namespace std;
using namespace boost::multi_index;

struct TimeTag{};

template<typename Container, typename SenderReceiver> class Inflighter
{
public:
  Inflighter(Container& c, SenderReceiver& sr) : d_container(c), d_sr(sr), d_init(false)
  {
    d_burst = 2;
    d_maxInFlight = 5;
    d_timeoutSeconds = 3;
    d_unexpectedResponse = d_timeouts = 0;
  }
  void init()
  {
    d_iter = d_container.begin();
    d_init=true;
  }
  void run();
  
  unsigned int d_maxInFlight;
  unsigned int d_timeoutSeconds;
  int d_burst;
  
private:
  struct TTDItem
  {
    typename Container::iterator iter;
    typename SenderReceiver::Identifier id;
    struct timeval ttd;
  };

  typedef multi_index_container<
    TTDItem,
    indexed_by<
      ordered_unique<
	member<TTDItem, typename SenderReceiver::Identifier, &TTDItem::id>
      >,
      ordered_non_unique<
	tag<TimeTag>,
	member<TTDItem, struct timeval, &TTDItem::ttd>
      >
    >
  >ttdwatch_t; 
  
  Container& d_container;
  SenderReceiver& d_sr;
  
  
  
  ttdwatch_t d_ttdWatch;
  typename Container::iterator d_iter;
  bool d_init;
  
  uint64_t d_unexpectedResponse, d_timeouts;
};

template<typename Container, typename SendReceive> void Inflighter<Container, SendReceive>::run()
{
  if(!d_init)
    init();
    
  // cout << "Have "<<d_container.size() << " things to do!"<<endl;
  
  for(;;) {
    int burst = 0;
    while(d_iter != d_container.end() && d_ttdWatch.size() < d_maxInFlight) { 
      TTDItem ttdi;
      ttdi.iter = ++d_iter;
      ttdi.id = d_sr.send(*ttdi.iter);
      gettimeofday(&ttdi.ttd, 0);
      ttdi.ttd.tv_sec += d_timeoutSeconds;
      
      d_ttdWatch.insert(ttdi);
      
      if(++burst == d_burst)
        break;
    }
    int processed=0;
    if(!d_ttdWatch.empty()) {
      // cerr<<"Have "<< d_ttdWatch.size() <<" queries in flight"<<endl;	    
      typename SendReceive::Answer answer;
      typename SendReceive::Identifier id;
      
      while(d_sr.receive(id, answer)) {
	typename ttdwatch_t::iterator ival = d_ttdWatch.find(id);
        if(ival != d_ttdWatch.end()) {
	  ++processed;
	  // cerr<<"Received expected item with id '"<<id<<"' and value '"<<item<<"'"<<endl;
	  d_sr.deliverAnswer(*ival->iter, answer);
	  d_ttdWatch.erase(ival);
	  break; // we can send new questions!
	}
	else {
	 // cerr<<"UNEXPECTED ANSWER!"<<endl;
	  d_unexpectedResponse++;
	}
      }
    
      
      if(!processed) { // no new responses, time for some cleanup
        struct timeval now;
        gettimeofday(&now, 0);
	
	typedef typename ttdwatch_t::template index<TimeTag>::type waiters_by_ttd_index_t;
	waiters_by_ttd_index_t& waiters_index = boost::multi_index::get<TimeTag>(d_ttdWatch);

        for(typename waiters_by_ttd_index_t::iterator valiter = waiters_index.begin(); valiter != waiters_index.end(); ) {
          if(valiter->ttd.tv_sec < now.tv_sec || (valiter->ttd.tv_sec == now.tv_sec && valiter->ttd.tv_usec < now.tv_usec)) {
            waiters_index.erase(valiter++);
	   // cerr<<"Have timeout"<<endl;
          }
	  else 
	    break;
        }
      }
    }
    if(d_ttdWatch.empty() && d_iter == d_container.end())
      break;
  }
}

#if 0
StatBag S;

struct SendReceive
{
  typedef int Identifier;
  typedef int Answer;
  ComboAddress d_remote;
  int d_socket;
  int d_id;
  
  SendReceive()
  {
    d_id = 0;
    d_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int val=1;
    setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    
    ComboAddress local("0.0.0.0", 1024);
    bind(d_socket, (struct sockaddr*)&local, local.getSocklen());
    
    char buf[512];
    
    socklen_t remotelen=sizeof(d_remote);
    cerr<<"Waiting for 'hi' on "<<local.toStringWithPort()<<endl;
    int len = recvfrom(d_socket, buf, sizeof(buf), 0, (struct sockaddr*)&d_remote, &remotelen);
    cerr<<d_remote.toStringWithPort()<<" sent 'hi': "<<string(buf, len);
    Utility::setNonBlocking(d_socket);
    connect(d_socket, (struct sockaddr*) &d_remote, d_remote.getSocklen());
  }
  
  ~SendReceive()
  {
    ::send(d_socket, "done\r\n", 6, 0);
  }
  
  Identifier send(int& i)
  {
    cerr<<"Sending a '"<<i<<"'"<<endl;
    string msg = (boost::format("%d %d\n") % d_id % i).str();
    ::send(d_socket, msg.c_str(), msg.length(), 0);
    return d_id++;
  }
  
  bool receive(Identifier& id, int& i)
  {
    if(waitForData(d_socket, 0, 500000) > 0) {
      char buf[512];
    
      int len = recv(d_socket, buf, sizeof(buf), 0);
      string msg(buf, len);
      if(sscanf(msg.c_str(), "%d %d", &id, &i) != 2) {
	throw runtime_error("Invalid input");
      }
      return 1;
    }
    return 0;
  }
  
  void deliverAnswer(int& i, int j)
  {
    cerr<<"We sent "<<i<<", got back: "<<j<<endl;
  }
};


int main()
{
  vector<int> numbers;
  SendReceive sr;
  Inflighter<vector<int>, SendReceive> inflighter(numbers, sr);

  for(int n=0; n < 100; ++n) 
    numbers.push_back(n*n);


  for(;;) {
    try {
      inflighter.run();
      break;
    }
    catch(exception& e) {
      cerr<<"Caught exception: "<<e.what()<<endl;
    }
  }
  
}
#endif
