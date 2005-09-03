/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 
    as published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "utility.hh" 
#include <iostream>
#include <errno.h>
#include <map>
#include <set>
#ifndef WIN32
#include <netdb.h>
#endif // WIN32
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "mtasker.hh"
#include <utility>
#include "dnspacket.hh"
#include "statbag.hh"
#include "arguments.hh"
#include "syncres.hh"
#include <fcntl.h>
#include <fstream>
#include "sstuff.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/shared_array.hpp>

using namespace boost;

#include "recursor_cache.hh"

#ifdef __FreeBSD__           // see cvstrac ticket #26
#include <pthread.h>
#include <semaphore.h>
#endif

MemRecursorCache RC;

string s_programname="pdns_recursor";

#if 0
#ifndef WIN32
#ifndef __FreeBSD__
extern "C" {
  int sem_init(sem_t*, int, unsigned int){return 0;}
  int sem_wait(sem_t*){return 0;}
  int sem_trywait(sem_t*){return 0;}
  int sem_post(sem_t*){return 0;}
  int sem_getvalue(sem_t*, int*){return 0;}
  pthread_t pthread_self(void){return (pthread_t) 0;}
  int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *mutexattr){ return 0; }
  int pthread_mutex_lock(pthread_mutex_t *mutex){ return 0; }
  int pthread_mutex_unlock(pthread_mutex_t *mutex) { return 0; }
  int pthread_mutex_destroy(pthread_mutex_t *mutex) { return 0; }
}
#endif // __FreeBSD__
#endif // WIN32
#endif

StatBag S;
ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}
static int d_clientsock;
static vector<int> d_udpserversocks;

typedef vector<int> tcpserversocks_t;
static tcpserversocks_t s_tcpserversocks;

struct PacketID
{
  PacketID() : sock(0), inNeeded(0), outPos(0)
  {}

  uint16_t id;  // wait for a specific id/remote paie
  struct sockaddr_in remote;  // this is the remote

  Socket* sock;  // or wait for an event on a TCP fd
  int inNeeded; // if this is set, we'll read until inNeeded bytes are read
  string inMSG; // they'll go here

  string outMSG; // the outgoing message that needs to be sent
  int outPos;    // how far we are along in the outMSG

  bool operator<(const PacketID& b) const
  {
    int ourSock= sock ? sock->getHandle() : 0;
    int bSock = b.sock ? b.sock->getHandle() : 0;
    return 
      tie(id, remote.sin_addr.s_addr, remote.sin_port, ourSock) <
      tie(b.id, b.remote.sin_addr.s_addr, b.remote.sin_port, bSock);
  }
};

static map<int,PacketID> d_tcpclientreadsocks, d_tcpclientwritesocks;

MTasker<PacketID,string>* MT;

int asendtcp(const string& data, Socket* sock) 
{
  PacketID pident;
  pident.sock=sock;
  pident.outMSG=data;
  string packet;

  //  cerr<<"asendtcp called for "<<data.size()<<" bytes"<<endl;
  d_tcpclientwritesocks[sock->getHandle()]=pident;

  int ret=MT->waitEvent(pident,&packet,1);
  if(!ret || ret==-1) { // timeout
    d_tcpclientwritesocks.erase(sock->getHandle());
  }
  return ret;
}

// -1 is error, 0 is timeout, 1 is success
int arecvtcp(string& data, int len, Socket* sock) 
{
  data="";
  PacketID pident;
  pident.sock=sock;
  pident.inNeeded=len;

  // cerr<<"arecvtcp called for "<<len<<" bytes"<<endl;
  // cerr<<d_tcpclientwritesocks.size()<<" write sockets"<<endl;
  d_tcpclientreadsocks[sock->getHandle()]=pident;

  int ret=MT->waitEvent(pident,&data,1);
  if(!ret || ret==-1) { // timeout
    d_tcpclientreadsocks.erase(sock->getHandle());
  }
  return ret;
}


/* these two functions are used by LWRes */
// -1 is error, > 1 is success
int asendto(const char *data, int len, int flags, struct sockaddr *toaddr, int addrlen, int id) 
{
  return sendto(d_clientsock, data, len, flags, toaddr, addrlen);
}

// -1 is error, 0 is timeout, 1 is success
int arecvfrom(char *data, int len, int flags, struct sockaddr *toaddr, Utility::socklen_t *addrlen, int *d_len, int id)
{
  PacketID pident;
  pident.id=id;
  memcpy(&pident.remote,toaddr,sizeof(pident.remote));

  string packet;
  int ret=MT->waitEvent(pident,&packet,1);
  if(ret > 0) {
    *d_len=packet.size();
    memcpy(data,packet.c_str(),min(len,*d_len));
  }

  return ret;
}


static void writePid(void)
{
  string fname=arg()["socket-dir"]+"/"+s_programname+".pid";
  ofstream of(fname.c_str());
  if(of)
    of<<getpid()<<endl;
  else
    L<<Logger::Error<<"Requested to write pid for "<<getpid()<<" to "<<fname<<" failed: "<<strerror(errno)<<endl;
}

void primeHints(void)
{
  // prime root cache

  static char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
		     "192.36.148.17","192.58.128.30", "193.0.14.129", "198.32.64.12", "202.12.27.33"};
  DNSResourceRecord arr, nsrr;
  arr.qtype=QType::A;
  arr.ttl=time(0)+3600000;
  nsrr.qtype=QType::NS;
  nsrr.ttl=time(0)+3600000;
  
  set<DNSResourceRecord>nsset;
  for(char c='a';c<='m';++c) {
    static char templ[40];
    strncpy(templ,"a.root-servers.net", sizeof(templ) - 1);
    *templ=c;
    arr.qname=nsrr.content=templ;
    arr.content=ips[c-'a'];
    set<DNSResourceRecord>aset;
    aset.insert(arr);
    RC.replace(string(templ),QType(QType::A),aset);

    nsset.insert(nsrr);
  }
  RC.replace("",QType(QType::NS),nsset); // and stuff in the cache
}

void startDoResolve(void *p)
{
  try {
    bool quiet=arg().mustDo("quiet");
    DNSPacket P=*(DNSPacket *)p;

    delete (DNSPacket *)p;
    
    vector<DNSResourceRecord>ret;
    DNSPacket *R=P.replyPacket();
    R->setA(false);
    R->setRA(true);
    //    MT->setTitle("udp question for "+P.qdomain+"|"+P.qtype.getName());
    SyncRes sr;
    if(!quiet)
      L<<Logger::Error<<"["<<MT->getTid()<<"] " << (R->d_tcp ? "TCP " : "") << "question for '"<<P.qdomain<<"|"<<P.qtype.getName()<<"' from "<<P.getRemote()<<endl;

    sr.setId(MT->getTid());
    if(!P.d.rd)
      sr.setCacheOnly();

    int res=sr.beginResolve(P.qdomain, P.qtype, ret);
    if(res<0)
      R->setRcode(RCode::ServFail);
    else {
      R->setRcode(res);
      for(vector<DNSResourceRecord>::const_iterator i=ret.begin();i!=ret.end();++i)
	R->addRecord(*i);
    }

    const char *buffer=R->getData();

    if(!R->d_tcp) {
      if(R->len > 512) {
	R->truncate(512);
      }

      sendto(R->getSocket(),buffer,R->len,0,(struct sockaddr *)(R->remote),R->d_socklen);
    }
    else {
      char buf[2];
      buf[0]=R->len/256;
      buf[1]=R->len%256;

      struct iovec iov[2];

      iov[0].iov_base=(void*)buf;    iov[0].iov_len=2;
      iov[1].iov_base=(void*)buffer; iov[1].iov_len = R->len;

      int ret=writev(R->getSocket(), iov, 2);

      if(ret <= 0 ) 
	L<<Logger::Error<<"Error writing TCP answer to "<<P.getRemote()<<": "<< (ret ? strerror(errno) : "EOF") <<endl;
      else if(ret != 2 + R->len)
	L<<Logger::Error<<"Oops, partial answer sent to "<<P.getRemote()<<" - probably would have trouble receiving our answer anyhow (size="<<R->len<<")"<<endl;

      //      if(write(R->getSocket(),buf,2)!=2 || write(R->getSocket(),buffer,R->len)!=R->len)
      //  XXX FIXME write this writev fallback otherwise
    }

    //    MT->setTitle("DONE! udp question for "+P.qdomain+"|"+P.qtype.getName());
    if(!quiet) {
      L<<Logger::Error<<"["<<MT->getTid()<<"] answer to "<<(P.d.rd?"":"non-rd ")<<"question '"<<P.qdomain<<"|"<<P.qtype.getName();
      L<<"': "<<ntohs(R->d.ancount)<<" answers, "<<ntohs(R->d.arcount)<<" additional, took "<<sr.d_outqueries<<" packets, "<<
	sr.d_throttledqueries<<" throttled, "<<sr.d_timeouts<<" timeouts, "<<sr.d_tcpoutqueries<<" tcp connections, rcode="<<res<<endl;
    }
    
    sr.d_outqueries ? RC.cacheMisses++ : RC.cacheHits++; 

    delete R;
  }
  catch(AhuException &ae) {
    L<<Logger::Error<<"startDoResolve problem: "<<ae.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Any other exception in a resolver context"<<endl;
  }
}

void makeClientSocket()
{
  d_clientsock=socket(AF_INET, SOCK_DGRAM,0);
  if(d_clientsock<0) 
    throw AhuException("Making a socket for resolver: "+stringerror());
  
  struct sockaddr_in sin;
  memset((char *)&sin,0, sizeof(sin));
  
  sin.sin_family = AF_INET;

  if(!IpToU32(arg()["query-local-address"], &sin.sin_addr.s_addr))
    throw AhuException("Unable to resolve local address '"+ arg()["query-local-address"] +"'"); 

  int tries=10;
  while(--tries) {
    uint16_t port=10000+Utility::random()%10000;
    sin.sin_port = htons(port); 
    
    if (bind(d_clientsock, (struct sockaddr *)&sin, sizeof(sin)) >= 0) 
      break;
    
  }
  if(!tries)
    throw AhuException("Resolver binding to local socket: "+stringerror());

  Utility::setNonBlocking(d_clientsock);
  L<<Logger::Error<<"Sending UDP queries from "<<inet_ntoa(sin.sin_addr)<<":"<< ntohs(sin.sin_port)  <<endl;
}

void makeTCPServerSockets()
{
  vector<string>locals;
  stringtok(locals,arg()["local-address"]," ,");

  if(locals.empty())
    throw AhuException("No local address specified");
  
  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    int fd=socket(AF_INET, SOCK_STREAM,0);
    if(fd<0) 
      throw AhuException("Making a server socket for resolver: "+stringerror());
  
    struct sockaddr_in sin;
    memset((char *)&sin,0, sizeof(sin));
    
    sin.sin_family = AF_INET;
    if(!IpToU32(*i, &sin.sin_addr.s_addr))
      throw AhuException("Unable to resolve local address '"+ *i +"'"); 

    int tmp=1;
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) {
      L<<Logger::Error<<"Setsockopt failed for TCP listening socket"<<endl;
      exit(1);  
    }
    
    sin.sin_port = htons(arg().asNum("local-port")); 
    
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin))<0) 
      throw AhuException("Binding TCP server socket for "+*i+": "+stringerror());
    
    Utility::setNonBlocking(fd);
    listen(fd, 128);
    s_tcpserversocks.push_back(fd);
    L<<Logger::Error<<"Listening for TCP queries on "<<inet_ntoa(sin.sin_addr)<<":"<<arg().asNum("local-port")<<endl;
  }
}

void makeUDPServerSockets()
{
  vector<string>locals;
  stringtok(locals,arg()["local-address"]," ,");

  if(locals.empty())
    throw AhuException("No local address specified");
  
  if(arg()["local-address"]=="0.0.0.0") {
    L<<Logger::Warning<<"It is advised to bind to explicit addresses with the --local-address option"<<endl;
  }

  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    int fd=socket(AF_INET, SOCK_DGRAM,0);
    if(fd<0) 
      throw AhuException("Making a server socket for resolver: "+stringerror());
  
    struct sockaddr_in sin;
    memset((char *)&sin,0, sizeof(sin));
    
    sin.sin_family = AF_INET;
    if(!IpToU32(*i, &sin.sin_addr.s_addr))
      throw AhuException("Unable to resolve local address '"+ *i +"'"); 
    
    sin.sin_port = htons(arg().asNum("local-port")); 
    
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin))<0) 
      throw AhuException("Resolver binding to server socket for "+*i+": "+stringerror());
    
    Utility::setNonBlocking(fd);
    d_udpserversocks.push_back(fd);
    L<<Logger::Error<<"Listening for UDP queries on "<<inet_ntoa(sin.sin_addr)<<":"<<arg().asNum("local-port")<<endl;
  }
}


#ifndef WIN32
void daemonize(void)
{
  if(fork())
    exit(0); // bye bye
  
  setsid(); 

  // cleanup open fds, but skip sockets 
  close(0);
  close(1);
  close(2);

}
#endif

int counter, qcounter;
bool statsWanted;

void usr1Handler(int)
{
  statsWanted=true;
}

void usr2Handler(int)
{
  SyncRes::setLog(true);
}



void doStats(void)
{
  if(qcounter) {
    L<<Logger::Error<<"stats: "<<qcounter<<" questions, "<<RC.size()<<" cache entries, "<<SyncRes::s_negcache.size()<<" negative entries, "
     <<(int)((RC.cacheHits*100.0)/(RC.cacheHits+RC.cacheMisses))<<"% cache hits";
    L<<Logger::Error<<", outpacket/query ratio "<<(int)(SyncRes::s_outqueries*100.0/SyncRes::s_queries)<<"%";
    L<<Logger::Error<<", "<<(int)(SyncRes::s_throttledqueries*100.0/(SyncRes::s_outqueries+SyncRes::s_throttledqueries))<<"% throttled, "
     <<SyncRes::s_nodelegated<<" no-delegation drops"<<endl;
    L<<Logger::Error<<"stats: "<<SyncRes::s_tcpoutqueries<<" outgoing tcp connections, "<<MT->numProcesses()<<" queries running, "<<SyncRes::s_outgoingtimeouts<<" outgoing timeouts"<<endl;
  }
  else if(statsWanted) 
    L<<Logger::Error<<"stats: no stats yet!"<<endl;

  statsWanted=false;
}

void houseKeeping(void *)
{
  static time_t last_stat, last_rootupdate, last_prune;
  time_t now=time(0);
  if(now - last_prune > 60) { 
    RC.doPrune();
    last_prune=time(0);
  }
  if(now - last_stat>1800) { 
    doStats();
    last_stat=time(0);
  }
  if(now -last_rootupdate>7200) {
    SyncRes sr;
    vector<DNSResourceRecord>ret;

    sr.setNoCache();
    int res=sr.beginResolve("", QType(QType::NS), ret);
    if(!res) {
      L<<Logger::Error<<"Refreshed . records"<<endl;
      last_rootupdate=now;
    }
    else
      L<<Logger::Error<<"Failed to update . records, RCODE="<<res<<endl;
  }
}

struct TCPConnection
{
  int fd;
  enum {BYTE0, BYTE1, GETQUESTION} state;
  int qlen;
  int bytesread;
  struct sockaddr_in remote;
  char data[65535];
  time_t startTime;
};

#if 0

#include <execinfo.h>

static void maketrace()
{
  void *array[20]; //only care about last 17 functions (3 taken with tracing support)
  size_t size;
  char **strings;
  size_t i;

  size = backtrace (array, 20);
  strings = backtrace_symbols (array, size); //Need -rdynamic gcc (linker) flag for this to work

  for (i = 0; i < size; i++) //skip useless functions
    cout<<strings[i]<<"\n";
  cout<<"--"<<endl;
}

extern "C" {
int gettimeofday (struct timeval *__restrict __tv,
		  __timezone_ptr_t __tz)
{
  maketrace();
  return 0;
}

}
#endif 

int main(int argc, char **argv) 
{
  int ret = EXIT_SUCCESS;
#ifdef WIN32
    WSADATA wsaData;
    WSAStartup( MAKEWORD( 2, 0 ), &wsaData );
#endif // WIN32

  try {
    Utility::srandom(time(0));
    arg().set("soa-minimum-ttl","Don't change")="0";
    arg().set("soa-serial-offset","Don't change")="0";
    arg().set("no-shuffle","Don't change")="off";
    arg().set("aaaa-additional-processing","turn on to do AAAA additional processing (slow)")="off";
    arg().set("local-port","port to listen on")="53";
    arg().set("local-address","IP addresses to listen on, separated by spaces or commas")="0.0.0.0";
    arg().set("trace","if we should output heaps of logging")="off";
    arg().set("daemon","Operate as a daemon")="yes";
    arg().set("chroot","switch to chroot jail")="";
    arg().set("setgid","If set, change group id to this gid for more security")="";
    arg().set("setuid","If set, change user id to this uid for more security")="";
    arg().set("quiet","Suppress logging of questions and answers")="true";
    arg().set("config-dir","Location of configuration directory (recursor.conf)")=SYSCONFDIR;
    arg().set("socket-dir","Where the controlsocket will live")=LOCALSTATEDIR;
    arg().set("delegation-only","Which domains we only accept delegations from")="";
    arg().set("query-local-address","Source IP address for sending queries")="0.0.0.0";
    arg().set("client-tcp-timeout","Timeout in seconds when talking to TCP clients")="2";
    arg().set("max-tcp-clients","Maximum number of simultaneous TCP clients")="128";

    arg().setCmd("help","Provide a helpful message");
    L.toConsole(Logger::Warning);
    arg().laxParse(argc,argv); // do a lax parse

    string configname=arg()["config-dir"]+"/recursor.conf";
    cleanSlashes(configname);

    if(!arg().file(configname.c_str())) 
      L<<Logger::Warning<<"Unable to parse configuration file '"<<configname<<"'"<<endl;

    arg().parse(argc,argv);

    arg().set("delegation-only")=toLower(arg()["delegation-only"]);

    if(arg().mustDo("help")) {
      cerr<<"syntax:"<<endl<<endl;
      cerr<<arg().helpstring(arg()["help"])<<endl;
      exit(99);
    }

    L.setName("pdns_recursor");

    L<<Logger::Warning<<"PowerDNS recursor "<<VERSION<<" (C) 2001-2005 PowerDNS.COM BV ("<<__DATE__", "__TIME__;
#ifdef __GNUC__
    L<<", gcc "__VERSION__;
#endif // add other compilers here
    L<<") starting up"<<endl;

  L<<Logger::Warning<<"PowerDNS comes with ABSOLUTELY NO WARRANTY. "
    "This is free software, and you are welcome to redistribute it "
    "according to the terms of the GPL version 2."<<endl;


    if(arg().mustDo("trace"))
      SyncRes::setLog(true);
    
    makeClientSocket();
    makeUDPServerSockets();
    makeTCPServerSockets();
        
    MT=new MTasker<PacketID,string>(100000);

    char data[1500];
    struct sockaddr_in fromaddr;
    
    PacketID pident;
    primeHints();    
    L<<Logger::Warning<<"Done priming cache with root hints"<<endl;
#ifndef WIN32
    if(arg().mustDo("daemon")) {
      L.toConsole(Logger::Critical);
      daemonize();
    }
    signal(SIGUSR1,usr1Handler);
    signal(SIGUSR2,usr2Handler);
    signal(SIGPIPE,SIG_IGN);

    writePid();
#endif

    int newgid=0;
    if(!arg()["setgid"].empty())
      newgid=Utility::makeGidNumeric(arg()["setgid"]);
    int newuid=0;
    if(!arg()["setuid"].empty())
      newuid=Utility::makeUidNumeric(arg()["setuid"]);


    if (!arg()["chroot"].empty()) {
        if (chroot(arg()["chroot"].c_str())<0) {
            L<<Logger::Error<<"Unable to chroot to '"+arg()["chroot"]+"': "<<strerror (errno)<<", exiting"<<endl;
	    exit(1);
	}
    }

    Utility::dropPrivs(newuid, newgid);

    vector<TCPConnection> tcpconnections;
    counter=0;
    time_t now=0;
    unsigned int maxTcpClients=arg().asNum("max-tcp-clients");
    for(;;) {
      while(MT->schedule()); // housekeeping, let threads do their thing
      
      if(!((counter++)%100)) 
	MT->makeThread(houseKeeping,0,"housekeeping");
      if(statsWanted)
	doStats();

      Utility::socklen_t addrlen=sizeof(fromaddr);
      int d_len;
      DNSPacket P;
      
      struct timeval tv;
      tv.tv_sec=0;
      tv.tv_usec=500000;
      
      fd_set readfds, writefds;
      FD_ZERO( &readfds );
      FD_ZERO( &writefds );
      FD_SET( d_clientsock, &readfds );
      int fdmax=d_clientsock;

      if(!tcpconnections.empty())
	now=time(0);

      vector<TCPConnection> sweeped;
      int tcpLimit=arg().asNum("client-tcp-timeout");
      for(vector<TCPConnection>::iterator i=tcpconnections.begin();i!=tcpconnections.end();++i) {
	if(now < i->startTime + tcpLimit) {
	  FD_SET(i->fd, &readfds);
	  fdmax=max(fdmax,i->fd);
	  sweeped.push_back(*i);
	}
	else {
	  L<<Logger::Error<<"TCP timeout from client "<<inet_ntoa(i->remote.sin_addr)<<endl;
	  close(i->fd);
	}
      }
      sweeped.swap(tcpconnections);

      for(vector<int>::const_iterator i=d_udpserversocks.begin(); i!=d_udpserversocks.end(); ++i) {
	FD_SET( *i, &readfds );
	fdmax=max(fdmax,*i);
      }
      if(tcpconnections.size() < maxTcpClients) 
	for(tcpserversocks_t::const_iterator i=s_tcpserversocks.begin(); i!=s_tcpserversocks.end(); ++i) {
	  FD_SET(*i, &readfds );
	  fdmax=max(fdmax,*i);
	}

      for(map<int,PacketID>::const_iterator i=d_tcpclientreadsocks.begin(); i!=d_tcpclientreadsocks.end(); ++i) {
	// cerr<<"Adding TCP socket "<<i->first<<" to read select set"<<endl;
	FD_SET( i->first, &readfds );
	fdmax=max(fdmax,i->first);
      }

      for(map<int,PacketID>::const_iterator i=d_tcpclientwritesocks.begin(); i!=d_tcpclientwritesocks.end(); ++i) {
	// cerr<<"Adding TCP socket "<<i->first<<" to write select set"<<endl;
	FD_SET( i->first, &writefds );
	fdmax=max(fdmax,i->first);
      }

      int selret = select(  fdmax + 1, &readfds, &writefds, NULL, &tv );
      if(selret<=0) 
	if (selret == -1 && errno!=EINTR) 
	  throw AhuException("Select returned: "+stringerror());
	else
	  continue;

      if(FD_ISSET(d_clientsock,&readfds)) { // do we have a question response?
	d_len=recvfrom(d_clientsock, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);    
	if(d_len<0) 
	  continue;
	
	P.setRemote((struct sockaddr *)&fromaddr, addrlen);
	if(P.parse(data,d_len)<0) {
	  L<<Logger::Error<<"Unparseable packet from remote server "<<P.getRemote()<<endl;
	}
	else { 
	  if(P.d.qr) {
	    pident.remote=fromaddr;
	    pident.id=P.d.id;
	    string packet;
	    packet.assign(data,d_len);
	    MT->sendEvent(pident,&packet);
	  }
	  else 
	    L<<Logger::Warning<<"Ignoring question on outgoing socket from "<<P.getRemote()<<endl;
	}
      }
      
      for(vector<int>::const_iterator i=d_udpserversocks.begin(); i!=d_udpserversocks.end(); ++i) {
	if(FD_ISSET(*i,&readfds)) { // do we have a new question on udp?
	  d_len=recvfrom(*i, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);    
	  if(d_len<0) 
	    continue;
	  P.setRemote((struct sockaddr *)&fromaddr, addrlen);
	  if(P.parse(data,d_len)<0) {
	    L<<Logger::Error<<"Unparseable packet from remote client "<<P.getRemote()<<endl;
	  }
	  else { 
	    if(P.d.qr)
	      L<<Logger::Error<<"Ignoring answer on server socket!"<<endl;
	    else {
	      ++qcounter;
	      P.setSocket(*i);
	      P.d_tcp=false;
	      MT->makeThread(startDoResolve,(void*)new DNSPacket(P), "udp");
	    }
	  }
	}
      }

      for(tcpserversocks_t::const_iterator i=s_tcpserversocks.begin(); i!=s_tcpserversocks.end(); ++i) { 
	if(FD_ISSET(*i ,&readfds)) { // do we have a new TCP connection
	  struct sockaddr_in addr;
	  socklen_t addrlen=sizeof(addr);
	  int newsock=accept(*i, (struct sockaddr*)&addr, &addrlen);
	  
	  if(newsock>0) {
	    Utility::setNonBlocking(newsock);
	    TCPConnection tc;
	    tc.fd=newsock;
	    tc.state=TCPConnection::BYTE0;
	    tc.remote=addr;
	    tc.startTime=time(0);
	    tcpconnections.push_back(tc);
	  }
	}
      }

      for(map<int,PacketID>::iterator i=d_tcpclientreadsocks.begin(); i!=d_tcpclientreadsocks.end();) { 
	bool haveErased=false;
	if(FD_ISSET(i->first, &readfds)) { // can we receive
	  shared_array<char> buffer(new char[i->second.inNeeded]);

	  int ret=read(i->first, buffer.get(), min(i->second.inNeeded,200));
	  // cerr<<"Read returned "<<ret<<endl;
	  if(ret > 0) {
	    i->second.inMSG.append(&buffer[0], &buffer[ret]);
	    i->second.inNeeded-=ret;
	    if(!i->second.inNeeded) {
	      // cerr<<"Got entire load of "<<i->second.inMSG.size()<<" bytes"<<endl;
	      PacketID pid=i->second;
	      string msg=i->second.inMSG;
	      
	      d_tcpclientreadsocks.erase((i++));
	      haveErased=true;
	      MT->sendEvent(pid, &msg);   // XXX DODGY
	    }
	    else {
	      // cerr<<"Still have "<<i->second.inNeeded<<" left to go"<<endl;
	    }
	  }
	  else {
	    //	    cerr<<"when reading ret="<<ret<<endl;
	    // XXX FIXME I think some stuff needs to happen here - like send an EOF event
	  }
	}
	if(!haveErased)
	  ++i;
      }

      for(map<int,PacketID>::iterator i=d_tcpclientwritesocks.begin(); i!=d_tcpclientwritesocks.end(); ) { 
	bool haveErased=false;
	if(FD_ISSET(i->first, &writefds)) { // can we send over TCP
	  // cerr<<"Socket "<<i->first<<" available for writing"<<endl;
	  int ret=write(i->first, i->second.outMSG.c_str(), i->second.outMSG.size() - i->second.outPos);
	  if(ret > 0) {
	    i->second.outPos+=ret;
	    if(i->second.outPos==i->second.outMSG.size()) {
	      // cerr<<"Sent out entire load of "<<i->second.outMSG.size()<<" bytes"<<endl;
	      PacketID pid=i->second;
	      d_tcpclientwritesocks.erase((i++));
	      MT->sendEvent(pid, 0);
	      haveErased=true;
	      // cerr<<"Sent event too"<<endl;
	    }

	  }
	  else { 
	    //	    cerr<<"ret="<<ret<<" when writing"<<endl;
	    // XXX FIXME I think some stuff needs to happen here - like send an EOF event
	  }
	}
	if(!haveErased)
	  ++i;
      }


      for(vector<TCPConnection>::iterator i=tcpconnections.begin();i!=tcpconnections.end();++i) {
	if(FD_ISSET(i->fd, &readfds)) {
	  if(i->state==TCPConnection::BYTE0) {
	    int bytes=read(i->fd,i->data,2);
	    if(bytes==1)
	      i->state=TCPConnection::BYTE1;
	    if(bytes==2) { 
	      i->qlen=(i->data[0]<<8)+i->data[1];
	      i->bytesread=0;
	      i->state=TCPConnection::GETQUESTION;
	    }
	    if(!bytes || bytes < 0) {
	      close(i->fd);
	      tcpconnections.erase(i);
	      break;
	    }
	  }
	  else if(i->state==TCPConnection::BYTE1) {
	    int bytes=read(i->fd,i->data+1,1);
	    if(bytes==1) {
	      i->state=TCPConnection::GETQUESTION;
	      i->qlen=(i->data[0]<<8)+i->data[1];
	      i->bytesread=0;
	    }
	    if(!bytes || bytes < 0) {
	      L<<Logger::Error<<"TCP Remote "<<sockAddrToString(&i->remote,sizeof(i->remote))<<" disconnected after first byte"<<endl;
	      close(i->fd);
	      tcpconnections.erase(i);
	      break;
	    }
	    
	  }
	  else if(i->state==TCPConnection::GETQUESTION) {
	    int bytes=read(i->fd,i->data + i->bytesread,i->qlen - i->bytesread);
	    if(!bytes || bytes < 0) {
	      L<<Logger::Error<<"TCP Remote "<<sockAddrToString(&i->remote,sizeof(i->remote))<<" disconnected while reading question body"<<endl;
	      close(i->fd);
	      tcpconnections.erase(i);
	      break;
	    }
	    i->bytesread+=bytes;
	    if(i->bytesread==i->qlen) {
	      i->state=TCPConnection::BYTE0;

	      if(P.parse(i->data,i->qlen)<0) {
		L<<Logger::Error<<"Unparseable packet from remote client "<<P.getRemote()<<endl;
		close(i->fd);
		tcpconnections.erase(i);
		break;
	      }
	      else { 
		P.setSocket(i->fd);
		P.d_tcp=true;
		P.setRemote((struct sockaddr *)&i->remote,sizeof(i->remote));
		if(P.d.qr)
		  L<<Logger::Error<<"Ignoring answer on server socket!"<<endl;
		else {
		  ++qcounter;
		  MT->makeThread(startDoResolve,(void*)new DNSPacket(P), "tcp");
		}
	      }
	    }
	  }
	}
      }
    }
  }
  catch(AhuException &ae) {
    L<<Logger::Error<<"Exception: "<<ae.reason<<endl;
    ret=EXIT_FAILURE;
  }
  catch(exception &e) {
    L<<Logger::Error<<"STL Exception: "<<e.what()<<endl;
    ret=EXIT_FAILURE;
  }
  catch(...) {
    L<<Logger::Error<<"any other exception in main: "<<endl;
    ret=EXIT_FAILURE;
  }
  
#ifdef WIN32
  WSACleanup();
#endif // WIN32

  return ret;
}
