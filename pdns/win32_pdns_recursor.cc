/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "utility.hh" 
#include <iostream>
#include <errno.h>
#include <map>
#include <set>
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
#include "recursorservice.hh"

string s_programname="recursor";

#ifndef WIN32
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

}
#endif // WIN32

StatBag S;
ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}
int d_clientsock;
int d_serversock;
int d_tcpserversock;

struct PacketID
{
  uint16_t id;
  struct sockaddr_in remote;
};

bool operator<(const PacketID& a, const PacketID& b)
{
  if(a.id<b.id)
    return true;

  if(a.id==b.id) {
    if(a.remote.sin_addr.s_addr < b.remote.sin_addr.s_addr)
      return true;
    if(a.remote.sin_addr.s_addr == b.remote.sin_addr.s_addr)
      if(a.remote.sin_port < b.remote.sin_port)
        return true;
  }

  return false;
}

MTasker<PacketID,string>* MT;

/* these two functions are used by LWRes */
int asendto(const char *data, int len, int flags, struct sockaddr *toaddr, int addrlen, int id) 
{
  return sendto(d_clientsock, data, len, flags, toaddr, addrlen);
}

int arecvfrom(char *data, int len, int flags, struct sockaddr *toaddr, Utility::socklen_t *addrlen, int *d_len, int id)
{
  PacketID pident;
  pident.id=id;
  memcpy(&pident.remote,toaddr,sizeof(pident.remote));

  string packet;
  if(!MT->waitEvent(pident,&packet,1)) { // timeout
    return 0; 
  }

  *d_len=packet.size();
  memcpy(data,packet.c_str(),min(len,*d_len));

  return 1;
}

typedef map<string,set<DNSResourceRecord> > cache_t;
static cache_t cache;
int cacheHits, cacheMisses;
int getCache(const string &qname, const QType& qt, set<DNSResourceRecord>* res)
{
  cache_t::const_iterator j=cache.find(toLower(qname)+"|"+qt.getName());
  if(j!=cache.end() && j->first==toLower(qname)+"|"+qt.getName() && j->second.begin()->ttl>(unsigned int)time(0)) {
    if(res)
      *res=j->second;

    return (unsigned int)j->second.begin()->ttl-time(0);
  }

  return -1;
}

void replaceCache(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content)
{

  // bogus code to generate root with very low ttl
  /*  
  if((0 && qname.empty()) || qname.rfind(".root-servers.net")==1) {
    cout<<"qname: '"<<qname<<"'"<<endl;
    set<DNSResourceRecord> changed;
    for(set<DNSResourceRecord>::const_iterator i=content.begin();i!=content.end();++i) {
      DNSResourceRecord j=*i;
      j.ttl=time(0)+20;
      changed.insert(j);
    }
    cache[qname+"|"+qt.getName()]=changed;
  }
  else
  */
    cache[toLower(qname)+"|"+qt.getName()]=content;
}

void doPrune(void)
{
  unsigned int names=0, records=0;

  for(cache_t::iterator j=cache.begin();j!=cache.end();){
    for(set<DNSResourceRecord>::iterator k=j->second.begin();k!=j->second.end();) 
      if((unsigned int)k->ttl < (unsigned int)time(0)) {
        j->second.erase(k++);
        records++;
      }
      else
        ++k;

    if(j->second.empty()) { // everything is gone
      cache.erase(j++);
      names++;

    }
    else {
      ++j;
    }
  }
}


void primeHints(void)
{
  // prime root cache
  static char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
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
    replaceCache(string(templ),QType(QType::A),aset);

    nsset.insert(nsrr);
  }
  replaceCache("",QType(QType::NS),nsset);
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

    SyncRes sr;
    if(!quiet)
      L<<Logger::Error<<"["<<MT->getTid()<<"] question for '"<<P.qdomain<<"|"<<P.qtype.getName()<<"' from "<<P.getRemote()<<endl;

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
    if(!R->getSocket())
      sendto(d_serversock,buffer,R->len,0,(struct sockaddr *)(R->remote),R->d_socklen);
    else {
      char buf[2];
      buf[0]=R->len/256;
      buf[1]=R->len%256;
      if(send(R->getSocket(),buf,2,0)!=2 || send(R->getSocket(),buffer,R->len,0)!=R->len)
        L<<Logger::Error<<"Oops, partial answer sent to "<<P.getRemote()<<" - probably would have trouble receiving our answer anyhow (size="<<R->len<<")"<<endl;
    }

    if(!quiet) {
      L<<Logger::Error<<"["<<MT->getTid()<<"] answer to "<<(P.d.rd?"":"non-rd ")<<"question '"<<P.qdomain<<"|"<<P.qtype.getName();
      L<<"': "<<ntohs(R->d.ancount)<<" answers, "<<ntohs(R->d.arcount)<<" additional, took "<<sr.d_outqueries<<" packets, "<<
        sr.d_throttledqueries<<" throttled, rcode="<<res<<endl;
    }
    
    sr.d_outqueries ? cacheMisses++ : cacheHits++;

    delete R;
  }
  catch(PDNSException &ae) {
    L<<Logger::Error<<"startDoResolve problem: "<<ae.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Any other exception in a resolver context"<<endl;
  }
}

void makeClientSocket()
{
  d_clientsock=socket(AF_INET, SOCK_DGRAM,0);
  Utility::setCloseOnExec(d_clientsock);

  if(d_clientsock<0) 
    throw PDNSException("Making a socket for resolver: "+stringerror());
  
  struct sockaddr_in sin;
  memset((char *)&sin,0, sizeof(sin));
  
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  
  int tries=10;
  while(--tries) {
    uint16_t port=10000+Utility::random()%10000;
    sin.sin_port = htons(port); 
    
    if (bind(d_clientsock, (struct sockaddr *)&sin, sizeof(sin)) >= 0) 
      break;
    
  }
  if(!tries)
    throw PDNSException("Resolver binding to local socket: "+stringerror());
}

void makeTCPServerSocket()
{
  d_tcpserversock=socket(AF_INET, SOCK_STREAM,0);
  Utility::setCloseOnExec(d_tcpserversock);

  if(d_tcpserversock<0) 
    throw PDNSException("Making a server socket for resolver: "+stringerror());
  
  struct sockaddr_in sin;
  memset((char *)&sin,0, sizeof(sin));
  
  sin.sin_family = AF_INET;

  if(arg()["local-address"]=="0.0.0.0") {
    sin.sin_addr.s_addr = INADDR_ANY;
  }
  else {
    if(!IpToU32(arg()["local-address"], &sin.sin_addr.s_addr))
      throw PDNSException("Unable to resolve local address"); 
  }

  sin.sin_port = htons(arg().asNum("local-port")); 
    
  if (bind(d_tcpserversock, (struct sockaddr *)&sin, sizeof(sin))<0) 
    throw PDNSException("TCP Resolver binding to server socket: "+stringerror());
  
  int tmp=1;
  if(setsockopt(d_tcpserversock,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) {
    L<<Logger::Error<<"Setsockopt failed"<<endl;
    exit(1);  
  }

  listen(d_tcpserversock, 128);
}

void makeServerSocket()
{
  d_serversock=socket(AF_INET, SOCK_DGRAM,0);
  Utility::setCloseOnExec(d_serversock);
  if(d_serversock<0) 
    throw PDNSException("Making a server socket for resolver: "+stringerror());
  
  struct sockaddr_in sin;
  memset((char *)&sin,0, sizeof(sin));
  
  sin.sin_family = AF_INET;

  if(arg()["local-address"]=="0.0.0.0") {
    L<<Logger::Warning<<"It is advised to bind to explicit addresses with the --local-address option"<<endl;
    sin.sin_addr.s_addr = INADDR_ANY;
  }
  else {
    
    if(!IpToU32(arg()["local-address"], &sin.sin_addr.s_addr))
      throw PDNSException("Unable to resolve local address"); 

  }

  sin.sin_port = htons(arg().asNum("local-port")); 
    
  if (bind(d_serversock, (struct sockaddr *)&sin, sizeof(sin))<0) 
    throw PDNSException("Resolver binding to server socket: "+stringerror());
  L<<Logger::Error<<"Incoming query source port: "<<arg().asNum("local-port")<<endl;
}

int counter, qcounter;
bool statsWanted;

void usr1Handler(int)
{
  statsWanted=true;
}


void doStats(void)
{
  if(qcounter) {
    L<<Logger::Error<<"stats: "<<qcounter<<" questions, "<<cache.size()<<" cache entries, "<<SyncRes::s_negcache.size()<<" negative entries, "
     <<(int)((cacheHits*100.0)/(cacheHits+cacheMisses))<<"% cache hits";
    L<<Logger::Error<<", outpacket/query ratio "<<(int)(SyncRes::s_outqueries*100.0/SyncRes::s_queries)<<"%";
    L<<Logger::Error<<", "<<(int)(SyncRes::s_throttledqueries*100.0/(SyncRes::s_outqueries+SyncRes::s_throttledqueries))<<"% throttled, "
     <<SyncRes::s_nodelegated<<" no-delegation drops"<<endl;
  }
  statsWanted=false;
}

void houseKeeping(void *)
{
  static time_t last_stat, last_rootupdate, last_prune;

  if(time(0)-last_stat>30) { 
    doPrune();
    last_prune=time(0);
  }
  if(time(0)-last_stat>1800) { 
    doStats();
    last_stat=time(0);
  }
  if(time(0)-last_rootupdate>7200) {
    SyncRes sr;
    vector<DNSResourceRecord>ret;

    sr.setNoCache();
    int res=sr.beginResolve("", QType(QType::NS), ret);
    if(!res) {
      L<<Logger::Error<<"Refreshed . records"<<endl;
      last_rootupdate=time(0);
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
};

//! Console handler.
BOOL WINAPI consoleHandler( DWORD ctrl )
{
  L << Logger::Error << "Recursor shutting down..." << endl;
  exit( 0 );

  // This will never be reached.
  return true;
} 


int serviceMain( int argc, char *argv[] )
{
  try
  {
    makeClientSocket();
    makeServerSocket();
    makeTCPServerSocket();
        
    MT=new MTasker<PacketID,string>(100000);

    char data[1500];
    struct sockaddr_in fromaddr;
    
    PacketID pident;
    primeHints();    
    L<<Logger::Warning<<"Done priming cache with root hints"<<endl;

    vector<TCPConnection> tcpconnections;
    for(;;) {
      while(MT->schedule()); // housekeeping, let threads do their thing
      
      if(!((counter++)%100)) 
        MT->makeThread(houseKeeping,0);
      if(statsWanted)
        doStats();

      Utility::socklen_t addrlen=sizeof(fromaddr);
      int d_len;
      DNSPacket P;
      
      struct timeval tv;
      tv.tv_sec=0;
      tv.tv_usec=500000;
      
      fd_set readfds;
      FD_ZERO( &readfds );
      FD_SET( d_clientsock, &readfds );
      FD_SET( d_serversock, &readfds );
      FD_SET( d_tcpserversock, &readfds );
      int fdmax=max(d_tcpserversock,max(d_clientsock,d_serversock));
      for(vector<TCPConnection>::const_iterator i=tcpconnections.begin();i!=tcpconnections.end();++i) {
        FD_SET(i->fd, &readfds);
        fdmax=max(fdmax,i->fd);
      }


      /* this should listen on a TCP port as well for new connections,  */
      int selret = select(  fdmax + 1, &readfds, NULL, NULL, &tv );
      if(selret<=0) 
        if (selret == -1 && errno!=EINTR) 
          throw PDNSException("Select returned: "+stringerror());
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
      
      if(FD_ISSET(d_serversock,&readfds)) { // do we have a new question on udp?
        d_len=recvfrom(d_serversock, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);    
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
            P.setSocket(0);
            MT->makeThread(startDoResolve,(void*)new DNSPacket(P));

          }
        }
      }

      if(FD_ISSET(d_tcpserversock,&readfds)) { // do we have a new TCP connection
        struct sockaddr_in addr;
  Utility::socklen_t addrlen=sizeof(addr);
        int newsock=accept(d_tcpserversock, (struct sockaddr*)&addr, &addrlen);
        Utility::setNonBlocking(newsock);
        
        if(newsock>0) {
          TCPConnection tc;
          tc.fd=newsock;
          tc.state=TCPConnection::BYTE0;
          tc.remote=addr;
          L<<Logger::Error<<"TCP Remote "<<sockAddrToString(&tc.remote,sizeof(tc.remote))<<" connected"<<endl;
          tcpconnections.push_back(tc);
        }
      }

      for(vector<TCPConnection>::iterator i=tcpconnections.begin();i!=tcpconnections.end();++i) {
        if(FD_ISSET(i->fd, &readfds)) {
          if(i->state==TCPConnection::BYTE0) {
            int bytes=recv(i->fd,i->data,2,0);
            if(bytes==1)
              i->state=TCPConnection::BYTE1;
            if(bytes==2) { 
              i->qlen=(i->data[0]<<8)+i->data[1];
              i->bytesread=0;
              i->state=TCPConnection::GETQUESTION;
            }
            if(!bytes || bytes < 0) {
              L<<Logger::Error<<"TCP Remote "<<sockAddrToString(&i->remote,sizeof(i->remote))<<" disconnected"<<endl;
        Utility::closesocket(i->fd);
              tcpconnections.erase(i);
              break;
            }
          }
          else if(i->state==TCPConnection::BYTE1) {
            int bytes=recv(i->fd,i->data+1,1,0);
            if(bytes==1) {
              i->state=TCPConnection::GETQUESTION;
              i->qlen=(i->data[0]<<8)+i->data[1];
              i->bytesread=0;
            }
            if(!bytes || bytes < 0) {
              L<<Logger::Error<<"TCP Remote "<<sockAddrToString(&i->remote,sizeof(i->remote))<<" disconnected after first byte"<<endl;
        Utility::closesocket(i->fd);
              tcpconnections.erase(i);
              break;
            }
            
          }
          else if(i->state==TCPConnection::GETQUESTION) {
            int bytes=recv(i->fd,i->data + i->bytesread,i->qlen - i->bytesread,0);
            if(!bytes || bytes < 0) {
              L<<Logger::Error<<"TCP Remote "<<sockAddrToString(&i->remote,sizeof(i->remote))<<" disconnected while reading question body"<<endl;
        Utility::closesocket(i->fd);
              tcpconnections.erase(i);
              break;
            }
            i->bytesread+=bytes;
            if(i->bytesread==i->qlen) {
              i->state=TCPConnection::BYTE0;

              if(P.parse(i->data,i->qlen)<0) {
        	L<<Logger::Error<<"Unparseable packet from remote client "<<P.getRemote()<<endl;
    Utility::closesocket(i->fd);
        	tcpconnections.erase(i);
        	break;
              }
              else { 
        	P.setSocket(i->fd);
        	P.setRemote((struct sockaddr *)&i->remote,sizeof(i->remote));
        	if(P.d.qr)
        	  L<<Logger::Error<<"Ignoring answer on server socket!"<<endl;
        	else {
        	  ++qcounter;
        	  MT->makeThread(startDoResolve,(void*)new DNSPacket(P));
        	}
              }
            }
          }
        }
      }
    }
  }
  catch(PDNSException &ae) {
    L<<Logger::Error<<"Exception: "<<ae.reason<<endl;
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"STL Exception: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"any other exception in main: "<<endl;
  }
  
#ifdef WIN32
  WSACleanup();
#endif // WIN32

  return 0;
}

int main(int argc, char **argv) 
{
  RecursorService recursor;

  // Initialize winsock.
  WSAData wsaData;

  if ( WSAStartup( MAKEWORD( 2, 0 ), &wsaData ) != 0 )
  {
    cerr << "Could not initialize winsock.dll" << endl;
    return -1;
  }

  try {

    Utility::srandom(time(0));
    arg().set("soa-minimum-ttl","Don't change")="0";
    arg().set("soa-serial-offset","Don't change")="0";
    arg().set("aaaa-additional-processing","turn on to do AAAA additional processing (slow)")="off";
    arg().set("local-port","port to listen on")="53";
    arg().set("local-address","port to listen on")="0.0.0.0";
    arg().set("trace","if we should output heaps of logging")="off";
    arg().set("daemon","Operate as a daemon")="yes";
    arg().set("quiet","Suppress logging of questions and answers")="off";
    arg().set("delegation-only","Which domains we only accept delegations from")="";
    arg().setCmd("help","Provide a helpful message");
    arg().set("config-dir","Location of configuration directory (recursor.conf)")="./";
    arg().setSwitch( "register-service", "Register the service" )= "no";
    arg().setSwitch( "unregister-service", "Unregister the service" )= "no";
    arg().setSwitch( "ntservice", "Run as service" )= "no";

    arg().setSwitch( "use-ntlog", "Use the NT logging facilities" )= "yes"; 
    arg().setSwitch( "use-logfile", "Use a log file" )= "no"; 
    arg().setSwitch( "logfile", "Filename of the log file" )= "recursor.log"; 

    L.toConsole(Logger::Warning);
    arg().laxParse(argc,argv); // do a lax parse

    // If we have to run as a nt service change the current directory to the executable directory.
    if ( arg().mustDo( "ntservice" ))
    {
      char    dir[ MAX_PATH ];
      string  newdir;

      GetModuleFileName( NULL, dir, sizeof( dir ));

      newdir = dir;
      newdir = newdir.substr( 0, newdir.find_last_of( "\\" ));

      SetCurrentDirectory( newdir.c_str());
    }

    string configname=arg()["config-dir"]+"/recursor.conf";
    cleanSlashes(configname);

    if(!arg().file(configname.c_str())) 
      L<<Logger::Warning<<"Unable to parse configuration file '"<<configname<<"'"<<endl;

    arg().parse(argc,argv);

    if ( arg().mustDo( "register-service" ))
    {
      if ( !recursor.registerService( "The PowerDNS Recursor.", true ))
      {
        cerr << "Could not register service." << endl;
        exit( 99 );
      }

      // Exit.
      exit( 0 );
    }

    if ( arg().mustDo( "unregister-service" ))
    {
      recursor.unregisterService();
      exit( 0 );
    }
    
    arg().set("delegation-only")=toLower(arg()["delegation-only"]);

    if(arg().mustDo("help")) {
      cerr<<"syntax:"<<endl<<endl;
      cerr<<arg().helpstring(arg()["help"])<<endl;
      exit(99);
    }

    L.setName("pdns_recursor");

    if(arg().mustDo("trace"))
      SyncRes::setLog(true);

    if ( arg().mustDo( "use-ntlog" ) && arg().mustDo( "ntservice" ))
      L.toNTLog();

    if ( arg().mustDo( "use-logfile" ))
      L.toFile( arg()[ "logfile" ] ); 
  
    // Register console control handler.
    if ( !arg().mustDo( "ntservice" ))
      SetConsoleCtrlHandler( consoleHandler, true );
  
    RecursorService::instance()->start( argc, argv, arg().mustDo( "ntservice" )); 

  }
  catch(PDNSException &ae) {
    L<<Logger::Error<<"Exception: "<<ae.reason<<endl;
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"STL Exception: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"any other exception in main: "<<endl;
  }
    
  return 0;
}
