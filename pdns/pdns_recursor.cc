/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2006  PowerDNS.COM BV

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
#ifndef WIN32
#include <netdb.h>
#endif // WIN32
#include "recursor_cache.hh"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include "mtasker.hh"
#include <utility>
#include "arguments.hh"
#include "syncres.hh"
#include <fcntl.h>
#include <fstream>
#include "sstuff.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/shared_array.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/function.hpp>
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "zoneparser-tng.hh"
#include "rec_channel.hh"
#include "logger.hh"
#include "iputils.hh"
#include "mplexer.hh"

#ifndef RECURSOR
#include "statbag.hh"
StatBag S;
#endif

FDMultiplexer* g_fdm;
unsigned int g_maxTCPPerClient;
bool g_logCommonErrors;
using namespace boost;

#ifdef __FreeBSD__           // see cvstrac ticket #26
#include <pthread.h>
#include <semaphore.h>
#endif

MemRecursorCache RC;
RecursorStats g_stats;
bool g_quiet;
NetmaskGroup* g_allowFrom;
string s_programname="pdns_recursor";
typedef vector<int> g_tcpListenSockets_t;
g_tcpListenSockets_t g_tcpListenSockets;
int g_tcpTimeout;

struct DNSComboWriter {
  DNSComboWriter(const char* data, uint16_t len, const struct timeval& now) : d_mdp(data, len), d_now(now), d_tcp(false), d_socket(-1)
  {}
  MOADNSParser d_mdp;
  void setRemote(ComboAddress* sa)
  {
    d_remote=*sa;
  }

  void setSocket(int sock)
  {
    d_socket=sock;
  }

  string getRemote() const
  {
    return d_remote.toString();
  }

  struct timeval d_now;
  ComboAddress d_remote;
  bool d_tcp;
  int d_socket;
};


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

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

struct timeval g_now;
typedef vector<int> tcpserversocks_t;

typedef MTasker<PacketID,string> MT_t;
MT_t* MT;


void handleTCPClientWritable(int fd, boost::any& var);

// -1 is error, 0 is timeout, 1 is success
int asendtcp(const string& data, Socket* sock) 
{
  PacketID pident;
  pident.sock=sock;
  pident.outMSG=data;

  g_fdm->addWriteFD(sock->getHandle(), handleTCPClientWritable, pident);
  string packet;

  int ret=MT->waitEvent(pident,&packet,1);
  if(!ret || ret==-1) { // timeout
    g_fdm->removeWriteFD(sock->getHandle());
  }
  else if(packet.size() !=data.size()) { // main loop tells us what it sent out, or empty in case of an error
    return -1;
  }
  return ret;
}

void handleTCPClientReadable(int fd, boost::any& var);

// -1 is error, 0 is timeout, 1 is success
int arecvtcp(string& data, int len, Socket* sock) 
{
  data.clear();
  PacketID pident;
  pident.sock=sock;
  pident.inNeeded=len;
  g_fdm->addReadFD(sock->getHandle(), handleTCPClientReadable, pident);

  int ret=MT->waitEvent(pident,&data,1);
  if(!ret || ret==-1) { // timeout
    g_fdm->removeReadFD(sock->getHandle());
  }
  else if(data.empty()) {// error, EOF or other
    return -1;
  }

  return ret;
}

// returns -1 for errors which might go away, throws for ones that won't
int makeClientSocket()
{
  int ret=socket(AF_INET, SOCK_DGRAM, 0);
  if(ret < 0 && errno==EMFILE) // this is not a catastrophic error
    return ret;

  if(ret<0) 
    throw AhuException("Making a socket for resolver: "+stringerror());

  static optional<struct sockaddr_in> sin;
  if(!sin) {
    struct sockaddr_in tmp;
    sin=tmp;
    memset((char *)&*sin,0, sizeof(sin));
    sin->sin_family = AF_INET;
    
    if(!IpToU32(::arg()["query-local-address"], &sin->sin_addr.s_addr))
      throw AhuException("Unable to resolve local address '"+ ::arg()["query-local-address"] +"'"); 
  }
  
  int tries=10;
  while(--tries) {
    uint16_t port=1025+Utility::random()%64510;
    if(tries==1)  // fall back to kernel 'random'
	port=0;

    sin->sin_port = htons(port); 
    
    if (::bind(ret, (struct sockaddr *)&*sin, sizeof(*sin)) >= 0) 
      break;
  }
  if(!tries)
    throw AhuException("Resolver binding to local query client socket: "+stringerror());

  Utility::setNonBlocking(ret);
  return ret;
}

void handleUDPServerResponse(int fd, boost::any&);

// you can ask this class for a UDP socket to send a query from
// this socket is not yours, don't even think about deleting it
// but after you call 'returnSocket' on it, don't assume anything anymore
class UDPClientSocks
{
  unsigned int d_numsocks;
  unsigned int d_maxsocks;

public:
  UDPClientSocks() : d_numsocks(0), d_maxsocks(5000)
  {
  }

  typedef map<int,int> socks_t;
  socks_t d_socks;

  // returning -1 means: temporary OS error (ie, out of files)
  int getSocket()
  {
    pair<int, int> sock=make_pair(makeClientSocket(), 1);
    if(sock.first < 0) // temporary error - exception otherwise
      return -1;

    d_socks.insert(sock);
    d_numsocks++;
    return sock.first;
  }

  void returnSocket(int fd)
  {
    socks_t::iterator i=d_socks.find(fd);
    returnSocket(i);
  }

  // return a socket to the pool, or simply erase it
  void returnSocket(socks_t::iterator& i)
  {
    if(i==d_socks.end()) {
      throw AhuException("Trying to return a socket not in the pool");
    }
    g_fdm->removeReadFD(i->first);
    ::close(i->first);
    
    d_socks.erase(i++);
    --d_numsocks;
  }
}g_udpclientsocks;


/* these two functions are used by LWRes */
// -2 is OS error, -1 is error that depends on the remote, > 1 is success
int asendto(const char *data, int len, int flags, struct sockaddr *toaddr, int addrlen, int id, const string& domain, int* fd) 
{
  *fd=g_udpclientsocks.getSocket();
  if(*fd < 0)
    return -2;
  PacketID pident;
  pident.fd=*fd;
  pident.id=id;
  pident.domain=domain;
  memcpy(&pident.remote, toaddr, sizeof(pident.remote));
  
  int ret=connect(*fd, toaddr, addrlen);
  if(ret < 0)
    return ret;

  g_fdm->addReadFD(*fd, handleUDPServerResponse, pident);
  return send(*fd, data, len, 0);
}

// -1 is error, 0 is timeout, 1 is success
int arecvfrom(char *data, int len, int flags, struct sockaddr *toaddr, Utility::socklen_t *addrlen, int *d_len, int id, const string& domain, int fd)
{
  static optional<unsigned int> nearMissLimit;
  if(!nearMissLimit) 
    nearMissLimit=::arg().asNum("spoof-nearmiss-max");

  PacketID pident;
  pident.fd=fd;
  pident.id=id;
  pident.domain=domain;
  memcpy(&pident.remote, toaddr, sizeof(pident.remote));

  string packet;
  int ret=MT->waitEvent(pident, &packet, 1);
  if(ret > 0) {
    if(packet.empty()) {// means "error"
      return -1; 
    }

    *d_len=packet.size();
    memcpy(data,packet.c_str(),min(len,*d_len));
    if(*nearMissLimit && pident.nearMisses > *nearMissLimit) {
      L<<Logger::Error<<"Too many ("<<pident.nearMisses<<" > "<<*nearMissLimit<<") bogus answers for '"<<domain<<"' from "<<sockAddrToString((struct sockaddr_in*)toaddr)<<", assuming spoof attempt."<<endl;
      g_stats.spoofCount++;
      return -1;
    }
  }
  else {
    g_udpclientsocks.returnSocket(fd);
  }
  return ret;
}

void setBuffer(int fd, int optname, uint32_t size)
{
  uint32_t psize=0;
  socklen_t len=sizeof(psize);
  
  if(!getsockopt(fd, SOL_SOCKET, optname, (char*)&psize, &len) && psize > size) {
    L<<Logger::Error<<"Not decreasing socket buffer size from "<<psize<<" to "<<size<<endl;
    return; 
  }

  if (setsockopt(fd, SOL_SOCKET, optname, (char*)&size, sizeof(size)) < 0 )
    L<<Logger::Error<<"Warning: unable to raise socket buffer size to "<<size<<": "<<strerror(errno)<<endl;
}


static void setReceiveBuffer(int fd, uint32_t size)
{
  setBuffer(fd, SO_RCVBUF, size);
}

static void setSendBuffer(int fd, uint32_t size)
{
  setBuffer(fd, SO_SNDBUF, size);
}

static void writePid(void)
{
  string fname=::arg()["socket-dir"]+"/"+s_programname+".pid";
  ofstream of(fname.c_str());
  if(of)
    of<< getpid() <<endl;
  else
    L<<Logger::Error<<"Requested to write pid for "<<getpid()<<" to "<<fname<<" failed: "<<strerror(errno)<<endl;
}

void primeHints(void)
{
  // prime root cache
  set<DNSResourceRecord>nsset;

  if(::arg()["hint-file"].empty()) {
    static char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
		       "192.36.148.17","192.58.128.30", "193.0.14.129", "198.32.64.12", "202.12.27.33"};
    DNSResourceRecord arr, nsrr;
    arr.qtype=QType::A;
    arr.ttl=time(0)+3600000;
    nsrr.qtype=QType::NS;
    nsrr.ttl=time(0)+3600000;
    
    for(char c='a';c<='m';++c) {
      static char templ[40];
      strncpy(templ,"a.root-servers.net.", sizeof(templ) - 1);
      *templ=c;
      arr.qname=nsrr.content=templ;
      arr.content=ips[c-'a'];
      set<DNSResourceRecord> aset;
      aset.insert(arr);
      RC.replace(string(templ), QType(QType::A), aset);
      
      nsset.insert(nsrr);
    }
  }
  else {
    ZoneParserTNG zpt(::arg()["hint-file"]);
    DNSResourceRecord rr;
    set<DNSResourceRecord> aset;

    while(zpt.get(rr)) {
      rr.ttl+=time(0);
      if(rr.qtype.getCode()==QType::A) {
	set<DNSResourceRecord> aset;
	aset.insert(rr);
	RC.replace(rr.qname, QType(QType::A), aset);
      }
      if(rr.qtype.getCode()==QType::NS) {
	rr.content=toLower(rr.content);
	nsset.insert(rr);
      }
    }
  }
  RC.replace(".", QType(QType::NS), nsset); // and stuff in the cache
}

map<ComboAddress, uint32_t> g_tcpClientCounts;

struct TCPConnection
{
  int fd;
  enum stateenum {BYTE0, BYTE1, GETQUESTION, DONE} state;
  int qlen;
  int bytesread;
  ComboAddress remote;
  char data[65535];
  time_t startTime;

  void closeAndCleanup()
  {
    close(fd);
    if(!g_tcpClientCounts[remote]--) 
      g_tcpClientCounts.erase(remote);
    s_currentConnections--;
  }
  static unsigned int s_currentConnections; //!< total number of current TCP connections
};

unsigned int TCPConnection::s_currentConnections; 

void startDoResolve(void *p)
{
  DNSComboWriter* dc=(DNSComboWriter *)p;
  try {
    uint16_t maxudpsize=512;
    MOADNSParser::EDNSOpts edo;
    if(dc->d_mdp.getEDNSOpts(&edo)) {
      maxudpsize=edo.d_packetsize;
    }
    
    vector<DNSResourceRecord> ret;
    
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_mdp.d_qclass);

    pw.getHeader()->aa=0;
    pw.getHeader()->ra=1;
    pw.getHeader()->qr=1;
    pw.getHeader()->id=dc->d_mdp.d_header.id;
    pw.getHeader()->rd=dc->d_mdp.d_header.rd;

    SyncRes sr(dc->d_now);
    if(!g_quiet)
      L<<Logger::Error<<"["<<MT->getTid()<<"] " << (dc->d_tcp ? "TCP " : "") << "question for '"<<dc->d_mdp.d_qname<<"|"
       <<DNSRecordContent::NumberToType(dc->d_mdp.d_qtype)<<"' from "<<dc->getRemote()<<endl;

    sr.setId(MT->getTid());
    if(!dc->d_mdp.d_header.rd)
      sr.setCacheOnly();

    int res=sr.beginResolve(dc->d_mdp.d_qname, QType(dc->d_mdp.d_qtype), dc->d_mdp.d_qclass, ret);
    if(res<0) {
      pw.getHeader()->rcode=RCode::ServFail;
      // no commit here, because no record
      g_stats.servFails++;
    }
    else {
      pw.getHeader()->rcode=res;
      switch(res) {
      case RCode::ServFail:
	g_stats.servFails++;
	break;
      case RCode::NXDomain:
	g_stats.nxDomains++;
	break;
      case RCode::NoError:
	g_stats.noErrors++;
	break;
      }
      
      if(ret.size()) {
	shuffle(ret);
	for(vector<DNSResourceRecord>::const_iterator i=ret.begin();i!=ret.end();++i) {
	  pw.startRecord(i->qname, i->qtype.getCode(), i->ttl, i->qclass, (DNSPacketWriter::Place)i->d_place);
	  shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(i->qtype.getCode(), i->qclass, i->content));
	  
	  drc->toPacket(pw);
	
	  if(!dc->d_tcp && pw.size() > maxudpsize) {
	    pw.rollback();
	    if(i->d_place==DNSResourceRecord::ANSWER)  // only truncate if we actually omitted parts of the answer
	      pw.getHeader()->tc=1;
	    goto sendit; // need to jump over pw.commit
	  }
	}
	pw.commit();
      }
    }
  sendit:;
    if(!dc->d_tcp) {
      sendto(dc->d_socket, &*packet.begin(), packet.size(), 0, (struct sockaddr *)(&dc->d_remote), dc->d_remote.getSocklen());
    }
    else {
      char buf[2];
      buf[0]=packet.size()/256;
      buf[1]=packet.size()%256;

      struct iovec iov[2];

      iov[0].iov_base=(void*)buf;              iov[0].iov_len=2;
      iov[1].iov_base=(void*)&*packet.begin(); iov[1].iov_len = packet.size();

      int ret=writev(dc->d_socket, iov, 2);
      bool hadError=true;

      if(ret == 0) 
	L<<Logger::Error<<"EOF writing TCP answer to "<<dc->getRemote()<<endl;
      else if(ret < 0 )  
	L<<Logger::Error<<"Error writing TCP answer to "<<dc->getRemote()<<": "<< strerror(errno) <<endl;
      else if((unsigned int)ret != 2 + packet.size())
	L<<Logger::Error<<"Oops, partial answer sent to "<<dc->getRemote()<<" for "<<dc->d_mdp.d_qname<<" (size="<< (2 + packet.size()) <<", sent "<<ret<<")"<<endl;
      else
	hadError=false;
      
      // update tcp connection status, either by closing or moving to 'BYTE0'

      if(hadError) {
	g_fdm->removeReadFD(dc->d_socket);
	close(dc->d_socket);
      }
      else {
	any_cast<TCPConnection>(&g_fdm->getReadParameter(dc->d_socket))->state=TCPConnection::BYTE0;
	struct timeval now; 
	gettimeofday(&now, 0); // needs to be updated
	g_fdm->setReadTTD(dc->d_socket, now, g_tcpTimeout);
      }
    }

    if(!g_quiet) {
      L<<Logger::Error<<"["<<MT->getTid()<<"] answer to "<<(dc->d_mdp.d_header.rd?"":"non-rd ")<<"question '"<<dc->d_mdp.d_qname<<"|"<<DNSRecordContent::NumberToType(dc->d_mdp.d_qtype);
      L<<"': "<<ntohs(pw.getHeader()->ancount)<<" answers, "<<ntohs(pw.getHeader()->arcount)<<" additional, took "<<sr.d_outqueries<<" packets, "<<
	sr.d_throttledqueries<<" throttled, "<<sr.d_timeouts<<" timeouts, "<<sr.d_tcpoutqueries<<" tcp connections, rcode="<<res<<endl;
    }
    
    sr.d_outqueries ? RC.cacheMisses++ : RC.cacheHits++; 
    float spent=makeFloat(sr.d_now-dc->d_now);
    if(spent < 0.001)
      g_stats.answers0_1++;
    else if(spent < 0.010)
      g_stats.answers1_10++;
    else if(spent < 0.1)
      g_stats.answers10_100++;
    else if(spent < 1.0)
      g_stats.answers100_1000++;
    else
      g_stats.answersSlow++;

    uint64_t newLat=(uint64_t)(spent*1000000);
    if(newLat < 1000000)  // outliers of several minutes exist..
      g_stats.avgLatencyUsec=(uint64_t)((1-0.0001)*g_stats.avgLatencyUsec + 0.0001*newLat);
    delete dc;
  }
  catch(AhuException &ae) {
    L<<Logger::Error<<"startDoResolve problem: "<<ae.reason<<endl;
  }
  catch(MOADNSException& e) {
    L<<Logger::Error<<"DNS parser error: "<<dc->d_mdp.d_qname<<", "<<e.what()<<endl;
  }
  catch(exception& e) {
    L<<Logger::Error<<"STL error: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Any other exception in a resolver context"<<endl;
  }
}

RecursorControlChannel s_rcc;

void makeControlChannelSocket()
{
  string sockname=::arg()["socket-dir"]+"/pdns_recursor.controlsocket";
  if(::arg().mustDo("fork")) {
    sockname+="."+lexical_cast<string>(getpid());
    L<<Logger::Warning<<"Forked control socket name: "<<sockname<<endl;
  }
  s_rcc.listen(sockname);
}

void handleRunningTCPQuestion(int fd, boost::any& var)
{
  TCPConnection* conn=any_cast<TCPConnection>(&var);
  if(conn->state==TCPConnection::BYTE0) {
    int bytes=read(conn->fd,conn->data,2);
    if(bytes==1)
      conn->state=TCPConnection::BYTE1;
    if(bytes==2) { 
      conn->qlen=(conn->data[0]<<8)+conn->data[1];
      conn->bytesread=0;
      conn->state=TCPConnection::GETQUESTION;
    }
    if(!bytes || bytes < 0) {
      TCPConnection tmp(*conn); 
      g_fdm->removeReadFD(fd);
      tmp.closeAndCleanup();
      return;
    }
  }
  else if(conn->state==TCPConnection::BYTE1) {
    int bytes=read(conn->fd,conn->data+1,1);
    if(bytes==1) {
      conn->state=TCPConnection::GETQUESTION;
      conn->qlen=(conn->data[0]<<8)+conn->data[1];
      conn->bytesread=0;
    }
    if(!bytes || bytes < 0) {
      if(g_logCommonErrors)
	L<<Logger::Error<<"TCP client "<< conn->remote.toString() <<" disconnected after first byte"<<endl;
      TCPConnection tmp(*conn); 
      g_fdm->removeReadFD(fd);
      tmp.closeAndCleanup();  // conn loses validity here..
      return;
    }
  }
  else if(conn->state==TCPConnection::GETQUESTION) {
    int bytes=read(conn->fd,conn->data + conn->bytesread,conn->qlen - conn->bytesread);
    if(!bytes || bytes < 0) {
      L<<Logger::Error<<"TCP client "<< conn->remote.toString() <<" disconnected while reading question body"<<endl;
      TCPConnection tmp(*conn);
      g_fdm->removeReadFD(fd);
      tmp.closeAndCleanup();  // conn loses validity here..

      return;
    }
    conn->bytesread+=bytes;
    if(conn->bytesread==conn->qlen) {
      conn->state=TCPConnection::DONE;        // this makes us immune from timeouts, from now on *we* are responsible
      DNSComboWriter* dc=0;
      try {
	dc=new DNSComboWriter(conn->data, conn->qlen, g_now);
      }
      catch(MOADNSException &mde) {
	g_stats.clientParseError++; 
	L<<Logger::Error<<"Unable to parse packet from TCP client "<< conn->remote.toString() <<endl;
	TCPConnection tmp(*conn); 
	g_fdm->removeReadFD(fd);
	tmp.closeAndCleanup();
	return;
      }
      
      dc->setSocket(conn->fd);
      dc->d_tcp=true;
      dc->setRemote(&conn->remote);
      if(dc->d_mdp.d_header.qr)
	L<<Logger::Error<<"Ignoring answer on server socket!"<<endl;
      else {
	++g_stats.qcounter;
	++g_stats.tcpqcounter;
	MT->makeThread(startDoResolve, dc);
	return;
      }
    }
  }
}

//! Handle new incoming TCP connection
void handleNewTCPQuestion(int fd, boost::any& )
{
  ComboAddress addr;
  socklen_t addrlen=sizeof(addr);
  int newsock=accept(fd, (struct sockaddr*)&addr, &addrlen);
  if(newsock>0) {
    g_stats.addRemote(addr);
    if(g_allowFrom && !g_allowFrom->match(&addr)) {
      g_stats.unauthorizedTCP++;
      close(newsock);
      return;
    }
    
    if(g_maxTCPPerClient && g_tcpClientCounts.count(addr) && g_tcpClientCounts[addr] >= g_maxTCPPerClient) {
      g_stats.tcpClientOverflow++;
      close(newsock); // don't call TCPConnection::closeAndCleanup here - did not enter it in the counts yet!
      return;
    }
    g_tcpClientCounts[addr]++;
    Utility::setNonBlocking(newsock);
    TCPConnection tc;
    tc.fd=newsock;
    tc.state=TCPConnection::BYTE0;
    tc.remote=addr;
    tc.startTime=g_now.tv_sec;
    TCPConnection::s_currentConnections++;
    g_fdm->addReadFD(tc.fd, handleRunningTCPQuestion, tc);
    struct timeval now;
    gettimeofday(&now, 0);
    g_fdm->setReadTTD(tc.fd, now, g_tcpTimeout);
  }
}

void handleNewUDPQuestion(int fd, boost::any& var)
{
  int len;
  char data[1500];
  ComboAddress fromaddr;
  socklen_t addrlen=sizeof(fromaddr);

  if((len=recvfrom(fd, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen)) >= 0) {
    g_stats.addRemote(fromaddr);
    if(g_allowFrom && !g_allowFrom->match(&fromaddr)) {
      g_stats.unauthorizedUDP++;
      return;
    }
    
    try {
      DNSComboWriter* dc = new DNSComboWriter(data, len, g_now);
      
      dc->setRemote(&fromaddr);
      
      if(dc->d_mdp.d_header.qr) {
	if(g_logCommonErrors)
	  L<<Logger::Error<<"Ignoring answer from "<<dc->getRemote()<<" on server socket!"<<endl;
      }
      else {
	++g_stats.qcounter;
	dc->setSocket(fd);
	dc->d_tcp=false;
	MT->makeThread(startDoResolve, (void*) dc);
      }
    }
    catch(MOADNSException& mde) {
      g_stats.clientParseError++; 
      L<<Logger::Error<<"Unable to parse packet from remote UDP client "<<fromaddr.toString() <<": "<<mde.what()<<endl;
    }
  }
}

typedef vector<pair<int, function< void(int, any&) > > > deferredAdd_t;
deferredAdd_t deferredAdd;

void makeTCPServerSockets()
{
  int fd;
  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");

  if(locals.empty())
    throw AhuException("No local address specified");
  
  ComboAddress sin;
  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    memset((char *)&sin,0, sizeof(sin));
    sin.sin4.sin_family = AF_INET;
    if(!IpToU32(*i, &sin.sin4.sin_addr.s_addr)) {
      sin.sin6.sin6_family = AF_INET6;
      if(inet_pton(AF_INET6, i->c_str(), &sin.sin6.sin6_addr) <= 0)
	throw AhuException("Unable to resolve local address '"+ *i +"'"); 
    }

    fd=socket(sin.sin6.sin6_family, SOCK_STREAM, 0);
    if(fd<0) 
      throw AhuException("Making a TCP server socket for resolver: "+stringerror());

    int tmp=1;
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) {
      L<<Logger::Error<<"Setsockopt failed for TCP listening socket"<<endl;
      exit(1);
    }
    
#ifdef TCP_DEFER_ACCEPT
    if(setsockopt(fd, SOL_TCP,TCP_DEFER_ACCEPT,(char*)&tmp,sizeof tmp) >= 0) {
      if(i==locals.begin())
	L<<Logger::Error<<"Enabled TCP data-ready filter for (slight) DoS protection"<<endl;
    }
#endif

    sin.sin4.sin_port = htons(::arg().asNum("local-port")); 
    int socklen=sin.sin4.sin_family==AF_INET ? sizeof(sin.sin4) : sizeof(sin.sin6);
    if (::bind(fd, (struct sockaddr *)&sin, socklen )<0) 
      throw AhuException("Binding TCP server socket for "+*i+": "+stringerror());
    
    Utility::setNonBlocking(fd);
    setSendBuffer(fd, 65000);
    listen(fd, 128);
    deferredAdd.push_back(make_pair(fd, handleNewTCPQuestion));
    //    g_fdm->addReadFD(fd, handleNewTCPQuestion);
    if(sin.sin4.sin_family == AF_INET) 
      L<<Logger::Error<<"Listening for TCP queries on "<< sin.toString() <<":"<<::arg().asNum("local-port")<<endl;
    else
      L<<Logger::Error<<"Listening for TCP queries on ["<< sin.toString() <<"]:"<<::arg().asNum("local-port")<<endl;
  }
}

void makeUDPServerSockets()
{
  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");

  if(locals.empty())
    throw AhuException("No local address specified");
  
  if(::arg()["local-address"]=="0.0.0.0") {
    L<<Logger::Warning<<"It is advised to bind to explicit addresses with the --local-address option"<<endl;
  }

  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    ComboAddress sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin4.sin_family = AF_INET;
    if(!IpToU32(*i, &sin.sin4.sin_addr.s_addr)) {
      sin.sin6.sin6_family = AF_INET6;
      if(inet_pton(AF_INET6, i->c_str(), &sin.sin6.sin6_addr) <= 0)
	throw AhuException("Unable to resolve local address '"+ *i +"'"); 
    }
    
    int fd=socket(sin.sin4.sin_family, SOCK_DGRAM,0);
    if(fd<0) 
      throw AhuException("Making a UDP server socket for resolver: "+stringerror());

    setReceiveBuffer(fd, 200000);
    sin.sin4.sin_port = htons(::arg().asNum("local-port")); 

    int socklen=sin.sin4.sin_family==AF_INET ? sizeof(sin.sin4) : sizeof(sin.sin6);
    if (::bind(fd, (struct sockaddr *)&sin, socklen)<0) 
      throw AhuException("Resolver binding to server socket for "+*i+": "+stringerror());
    
    Utility::setNonBlocking(fd);
    //    g_fdm->addReadFD(fd, handleNewUDPQuestion);
    deferredAdd.push_back(make_pair(fd, handleNewUDPQuestion));
    g_tcpListenSockets.push_back(fd);
    if(sin.sin4.sin_family == AF_INET) 
      L<<Logger::Error<<"Listening for UDP queries on "<< sin.toString() <<":"<<::arg().asNum("local-port")<<endl;
    else
      L<<Logger::Error<<"Listening for UDP queries on ["<< sin.toString() <<"]:"<<::arg().asNum("local-port")<<endl;
  }
}


#ifndef WIN32
void daemonize(void)
{
  if(fork())
    exit(0); // bye bye
  
  setsid(); 

  int i=open("/dev/null",O_RDWR); /* open stdin */
  if(i < 0) 
    L<<Logger::Critical<<"Unable to open /dev/null: "<<stringerror()<<endl;
  else {
    dup2(i,0); /* stdin */
    dup2(i,1); /* stderr */
    dup2(i,2); /* stderr */
    close(i);
  }
}
#endif

uint64_t counter;
bool statsWanted;


void usr1Handler(int)
{
  statsWanted=true;
}



void usr2Handler(int)
{
  SyncRes::setLog(true);
  g_quiet=false;
  ::arg().set("quiet")="no";

}

void doStats(void)
{
  if(g_stats.qcounter) {
    L<<Logger::Error<<"stats: "<<g_stats.qcounter<<" questions, "<<RC.size()<<" cache entries, "<<SyncRes::s_negcache.size()<<" negative entries, "
     <<(int)((RC.cacheHits*100.0)/(RC.cacheHits+RC.cacheMisses))<<"% cache hits"<<endl;
    L<<Logger::Error<<"stats: throttle map: "<<SyncRes::s_throttle.size()<<", ns speeds: "
     <<SyncRes::s_nsSpeeds.size()<<endl; // ", bytes: "<<RC.bytes()<<endl;
    L<<Logger::Error<<"stats: outpacket/query ratio "<<(int)(SyncRes::s_outqueries*100.0/SyncRes::s_queries)<<"%";
    L<<Logger::Error<<", "<<(int)(SyncRes::s_throttledqueries*100.0/(SyncRes::s_outqueries+SyncRes::s_throttledqueries))<<"% throttled, "
     <<SyncRes::s_nodelegated<<" no-delegation drops"<<endl;
    L<<Logger::Error<<"stats: "<<SyncRes::s_tcpoutqueries<<" outgoing tcp connections, "<<MT->numProcesses()<<" queries running, "<<SyncRes::s_outgoingtimeouts<<" outgoing timeouts"<<endl;
  }
  else if(statsWanted) 
    L<<Logger::Error<<"stats: no stats yet!"<<endl;

  statsWanted=false;
}

static void houseKeeping(void *)
{
  static time_t last_stat, last_rootupdate, last_prune;
  struct timeval now;
  gettimeofday(&now, 0);

  if(now.tv_sec - last_prune > 300) { 
    DTime dt;
    dt.setTimeval(now);
    RC.doPrune();
    
    typedef SyncRes::negcache_t::nth_index<1>::type negcache_by_ttd_index_t;
    negcache_by_ttd_index_t& ttdindex=boost::multi_index::get<1>(SyncRes::s_negcache);

    negcache_by_ttd_index_t::iterator i=ttdindex.lower_bound(now.tv_sec);
    ttdindex.erase(ttdindex.begin(), i);

    time_t limit=now.tv_sec-300;
    for(SyncRes::nsspeeds_t::iterator i = SyncRes::s_nsSpeeds.begin() ; i!= SyncRes::s_nsSpeeds.end(); )
      if(i->second.stale(limit))
	SyncRes::s_nsSpeeds.erase(i++);
      else
	++i;

    //   cerr<<"Pruned "<<pruned<<" records, left "<<SyncRes::s_negcache.size()<<"\n";
//    cout<<"Prune took "<<dt.udiff()<<"usec\n";
    last_prune=time(0);
  }
  if(now.tv_sec - last_stat>1800) { 
    doStats();
    last_stat=time(0);
  }
  if(now.tv_sec -last_rootupdate>7200) {
    SyncRes sr(now);
    vector<DNSResourceRecord> ret;

    sr.setNoCache();
    int res=sr.beginResolve(".", QType(QType::NS), 1, ret);
    if(!res) {
      L<<Logger::Error<<"Refreshed . records"<<endl;
      last_rootupdate=now.tv_sec;
    }
    else
      L<<Logger::Error<<"Failed to update . records, RCODE="<<res<<endl;
  }
}



#if 0
#include <execinfo.h>

  multimap<uint32_t,string> rev;
  for(map<string,uint32_t>::const_iterator i=casesptr->begin(); i!=casesptr->end(); ++i) {
    rev.insert(make_pair(i->second,i->first));
  }
  for(multimap<uint32_t,string>::const_iterator i=rev.begin(); i!= rev.end(); ++i) 
    cout<<i->first<<" times: \n"<<i->second<<"\n";

  cout.flush();

map<string,uint32_t>* casesptr;
static string maketrace()
{
  void *array[20]; //only care about last 17 functions (3 taken with tracing support)
  size_t size;
  char **strings;
  size_t i;

  size = backtrace (array, 5);
  strings = backtrace_symbols (array, size); //Need -rdynamic gcc (linker) flag for this to work

  string ret;

  for (i = 0; i < size; i++) //skip useless functions
    ret+=string(strings[i])+"\n";
  return ret;
}

extern "C" {

int gettimeofday (struct timeval *__restrict __tv,
		  __timezone_ptr_t __tz)
{
  static map<string, uint32_t> s_cases;
  casesptr=&s_cases;
  s_cases[maketrace()]++;
  __tv->tv_sec=time(0);
  return 0;
}

}
#endif

string questionExpand(const char* packet, uint16_t len)
{
  const char* end=packet+len;
  const char* pos=packet+12;
  unsigned char labellen;
  string ret;
  ret.reserve(len-12);
  while((labellen=*pos++)) {
    if(pos+labellen > end)
      break;
    ret.append(pos, labellen);
    ret.append(1,'.');
    pos+=labellen;
  }
  if(ret.empty())
    ret=".";
  return ret;
}


void handleRCC(int fd, boost::any& var)
{
  string remote;
  string msg=s_rcc.recv(&remote);
  RecursorControlParser rcp;
  RecursorControlParser::func_t* command;
  string answer=rcp.getAnswer(msg, &command);
  s_rcc.send(answer, &remote);
  command();
}

void handleTCPClientReadable(int fd, boost::any& var)
{
  PacketID* pident=any_cast<PacketID>(&var);
  //  cerr<<"handleTCPClientReadable called for fd "<<fd<<", pident->inNeeded: "<<pident->inNeeded<<", "<<pident->sock->getHandle()<<endl;

  shared_array<char> buffer(new char[pident->inNeeded]);

  int ret=read(fd, buffer.get(), pident->inNeeded);
  if(ret > 0) {
    pident->inMSG.append(&buffer[0], &buffer[ret]);
    pident->inNeeded-=ret;
    if(!pident->inNeeded) {
      //      cerr<<"Got entire load of "<<pident->inMSG.size()<<" bytes"<<endl;
      PacketID pid=*pident;
      string msg=pident->inMSG;
      
      g_fdm->removeReadFD(fd);
      MT->sendEvent(pid, &msg); 
    }
    else {
      //      cerr<<"Still have "<<pident->inNeeded<<" left to go"<<endl;
    }
  }
  else {
    PacketID tmp=*pident;
    g_fdm->removeReadFD(fd); // pident might now be invalid (it isn't, but still)
    string empty;
    MT->sendEvent(tmp, &empty); // this conveys error status
  }
}

void handleTCPClientWritable(int fd, boost::any& var)
{
  PacketID* pid=any_cast<PacketID>(&var);
  
  int ret=write(fd, pid->outMSG.c_str(), pid->outMSG.size() - pid->outPos);
  if(ret > 0) {
    pid->outPos+=ret;
    if(pid->outPos==pid->outMSG.size()) {
      PacketID tmp=*pid;
      g_fdm->removeWriteFD(fd);
      MT->sendEvent(tmp, &tmp.outMSG);  // send back what we sent to convey everything is ok
    }
  }
  else {  // error or EOF
    PacketID tmp(*pid);
    g_fdm->removeWriteFD(fd);
    string sent;
    MT->sendEvent(tmp, &sent);         // we convey error status by sending empty string
  }
}

void handleUDPServerResponse(int fd, boost::any& var)
{
  PacketID pid=any_cast<PacketID>(var);
  int len;
  char data[1500];
  struct sockaddr_in fromaddr;
  socklen_t addrlen=sizeof(fromaddr);

  len=recvfrom(fd, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);

  if(len < (int)sizeof(dnsheader)) {
    if(len < 0)
      ; //       cerr<<"Error on fd "<<fd<<": "<<stringerror()<<"\n";
    else {
      g_stats.serverParseError++; 
      if(g_logCommonErrors)
	L<<Logger::Error<<"Unable to parse packet from remote UDP server "<< sockAddrToString((struct sockaddr_in*) &fromaddr) <<
	  ": packet smalller than DNS header"<<endl;
    }
    string empty;
    g_udpclientsocks.returnSocket(fd);
    MT->sendEvent(pid, &empty); // this denotes error
    return;
  }  

  dnsheader dh;
  memcpy(&dh, data, sizeof(dh));
  
  if(!dh.qdcount) // UPC, Nominum?
    return;
  
  if(dh.qr) {
    PacketID pident;
    pident.remote=fromaddr;
    pident.id=dh.id;
    pident.fd=fd;
    pident.domain=questionExpand(data, len); // don't copy this from above - we need to do the actual read
    string packet;
    packet.assign(data, len);
    if(!MT->sendEvent(pident, &packet)) {
      // if(g_logCommonErrors)
      //   L<<Logger::Warning<<"Discarding unexpected packet from "<<sockAddrToString((struct sockaddr_in*) &fromaddr, addrlen)<<endl;
      g_stats.unexpectedCount++;
      
      for(MT_t::waiters_t::iterator mthread=MT->d_waiters.begin(); mthread!=MT->d_waiters.end(); ++mthread) {
	if(pident.fd==mthread->key.fd && !memcmp(&mthread->key.remote.sin_addr, &pident.remote.sin_addr, sizeof(pident.remote.sin_addr)) && 
	   !strcasecmp(pident.domain.c_str(), mthread->key.domain.c_str())) {
	  mthread->key.nearMisses++;
	}
      }
    }
    else 
      g_udpclientsocks.returnSocket(fd);
  }
  else
    L<<Logger::Warning<<"Ignoring question on outgoing socket from "<< sockAddrToString((struct sockaddr_in*) &fromaddr)  <<endl;
}

FDMultiplexer* getMultiplexer()
{
  FDMultiplexer* ret;
  for(FDMultiplexer::FDMultiplexermap_t::const_iterator i = FDMultiplexer::getMultiplexerMap().begin();
      i != FDMultiplexer::getMultiplexerMap().end(); ++i) {
    try {
      ret=i->second();
      L<<Logger::Error<<"Enabled '"<<ret->getName()<<"' multiplexer"<<endl;
      return ret;
    }
    catch(...)
      {}
  }
  L<<Logger::Error<<"No working multiplexer found!"<<endl;
  exit(1);
}

int main(int argc, char **argv) 
{
  reportBasicTypes();

  int ret = EXIT_SUCCESS;
#ifdef WIN32
    WSADATA wsaData;
    WSAStartup( MAKEWORD( 2, 0 ), &wsaData );
#endif // WIN32

  try {
    Utility::srandom(time(0));
    ::arg().set("soa-minimum-ttl","Don't change")="0";
    ::arg().set("soa-serial-offset","Don't change")="0";
    ::arg().set("no-shuffle","Don't change")="off";
    ::arg().set("aaaa-additional-processing","turn on to do AAAA additional processing (slow)")="off";
    ::arg().set("local-port","port to listen on")="53";
    ::arg().set("local-address","IP addresses to listen on, separated by spaces or commas")="127.0.0.1";
    ::arg().set("trace","if we should output heaps of logging")="off";
    ::arg().set("daemon","Operate as a daemon")="yes";
    ::arg().set("log-common-errors","If we should log rather common errors")="yes";
    ::arg().set("chroot","switch to chroot jail")="";
    ::arg().set("setgid","If set, change group id to this gid for more security")="";
    ::arg().set("setuid","If set, change user id to this uid for more security")="";
    ::arg().set("quiet","Suppress logging of questions and answers")="true";
    ::arg().set("config-dir","Location of configuration directory (recursor.conf)")=SYSCONFDIR;
    ::arg().set("socket-dir","Where the controlsocket will live")=LOCALSTATEDIR;
    ::arg().set("delegation-only","Which domains we only accept delegations from")="";
    ::arg().set("query-local-address","Source IP address for sending queries")="0.0.0.0";
    //    ::arg().set("query-local-port","Source port address for sending queries, defaults to random")="";
    ::arg().set("client-tcp-timeout","Timeout in seconds when talking to TCP clients")="2";
    ::arg().set("max-tcp-clients","Maximum number of simultaneous TCP clients")="128";
    ::arg().set("hint-file", "If set, load root hints from this file")="";
    ::arg().set("max-cache-entries", "If set, maximum number of entries in the main cache")="0";
    ::arg().set("max-negative-ttl", "maximum number of seconds to keep a negative cached entry in memory")="3600";
    ::arg().set("server-id", "Returned when queried for 'server.id' TXT, defaults to hostname")="";
    ::arg().set("remotes-ringbuffer-entries", "maximum number of packets to store statistics for")="0";
    ::arg().set("version-string", "string reported on version.pdns or version.bind")="PowerDNS Recursor "VERSION" $Id$";
    ::arg().set("allow-from", "If set, only allow these comma separated netmasks to recurse")="127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12";
    ::arg().set("max-tcp-per-client", "If set, maximum number of TCP sessions per client (IP address)")="0";
    ::arg().set("fork", "If set, fork the daemon for possible double performance")="no";
    ::arg().set("spoof-nearmiss-max", "If non-zero, assume spoofing after this many near misses")="20";
    ::arg().set("single-socket", "If set, only use a single socket for outgoing queries")="off";

    ::arg().setCmd("help","Provide a helpful message");
    ::arg().setCmd("config","Output blank configuration");
    L.toConsole(Logger::Warning);
    ::arg().laxParse(argc,argv); // do a lax parse

    string configname=::arg()["config-dir"]+"/recursor.conf";
    cleanSlashes(configname);

    if(!::arg().file(configname.c_str())) 
      L<<Logger::Warning<<"Unable to parse configuration file '"<<configname<<"'"<<endl;

    ::arg().parse(argc,argv);

    ::arg().set("delegation-only")=toLower(::arg()["delegation-only"]);

    if(::arg().mustDo("help")) {
      cerr<<"syntax:"<<endl<<endl;
      cerr<<::arg().helpstring(::arg()["help"])<<endl;
      exit(99);
    }

    if(::arg().mustDo("config")) {
      cout<<::arg().configstring()<<endl;
      exit(0);
    }


    L.setName("pdns_recursor");


    L<<Logger::Warning<<"PowerDNS recursor "<<VERSION<<" (C) 2001-2006 PowerDNS.COM BV ("<<__DATE__", "__TIME__;
#ifdef __GNUC__
    L<<", gcc "__VERSION__;
#endif // add other compilers here
    L<<") starting up"<<endl;

    L<<Logger::Warning<<"PowerDNS comes with ABSOLUTELY NO WARRANTY. "
      "This is free software, and you are welcome to redistribute it "
      "according to the terms of the GPL version 2."<<endl;

    L<<Logger::Warning<<"Operating in "<<(sizeof(unsigned long)*8) <<" bits mode"<<endl;

    if(!::arg()["allow-from"].empty()) {
      g_allowFrom=new NetmaskGroup;
      vector<string> ips;
      stringtok(ips, ::arg()["allow-from"], ", ");
      L<<Logger::Warning<<"Only allowing queries from: ";
      for(vector<string>::const_iterator i = ips.begin(); i!= ips.end(); ++i) {
	g_allowFrom->addMask(*i);
	if(i!=ips.begin())
	  L<<Logger::Warning<<", ";
	L<<Logger::Warning<<*i;
      }
      L<<Logger::Warning<<endl;
    }
    else if(::arg()["local-address"]!="127.0.0.1" && ::arg().asNum("local-port")==53)
      L<<Logger::Error<<"WARNING: Allowing queries from all IP addresses - this can be a security risk!"<<endl;
    
    g_quiet=::arg().mustDo("quiet");
    if(::arg().mustDo("trace")) {
      SyncRes::setLog(true);
      ::arg().set("quiet")="no";
      g_quiet=false;
    }

    SyncRes::s_maxnegttl=::arg().asNum("max-negative-ttl");
    SyncRes::s_serverID=::arg()["server-id"];
    if(SyncRes::s_serverID.empty()) {
      char tmp[128];
      gethostname(tmp, sizeof(tmp)-1);
      SyncRes::s_serverID=tmp;
    }

    g_stats.remotes.resize(::arg().asNum("remotes-ringbuffer-entries"));
    memset(&*g_stats.remotes.begin(), 0, g_stats.remotes.size() * sizeof(RecursorStats::remotes_t::value_type));
    g_logCommonErrors=::arg().mustDo("log-common-errors");

    makeUDPServerSockets();
    makeTCPServerSockets();

    if(::arg().mustDo("fork")) {
      fork();
      L<<Logger::Warning<<"This is forked pid "<<getpid()<<endl;
    }

    MT=new MTasker<PacketID,string>(100000);
    makeControlChannelSocket();        
    PacketID pident;
    primeHints();    
    L<<Logger::Warning<<"Done priming cache with root hints"<<endl;
#ifndef WIN32
    if(::arg().mustDo("daemon")) {
      L<<Logger::Warning<<"Calling daemonize, going to background"<<endl;
      L.toConsole(Logger::Critical);
      L.setLoglevel((Logger::Urgency)(4));

      daemonize();
    }
    g_fdm=getMultiplexer();

    for(deferredAdd_t::const_iterator i=deferredAdd.begin(); i!=deferredAdd.end(); ++i) 
      g_fdm->addReadFD(i->first, i->second);

    signal(SIGUSR1,usr1Handler);
    signal(SIGUSR2,usr2Handler);
    signal(SIGPIPE,SIG_IGN);

    writePid();
#endif

    int newgid=0;
    if(!::arg()["setgid"].empty())
      newgid=Utility::makeGidNumeric(::arg()["setgid"]);
    int newuid=0;
    if(!::arg()["setuid"].empty())
      newuid=Utility::makeUidNumeric(::arg()["setuid"]);


    if (!::arg()["chroot"].empty()) {
        if (chroot(::arg()["chroot"].c_str())<0) {
            L<<Logger::Error<<"Unable to chroot to '"+::arg()["chroot"]+"': "<<strerror (errno)<<", exiting"<<endl;
	    exit(1);
	}
    }

    Utility::dropPrivs(newuid, newgid);

    counter=0;
    unsigned int maxTcpClients=::arg().asNum("max-tcp-clients");
    g_tcpTimeout=::arg().asNum("client-tcp-timeout");

    g_maxTCPPerClient=::arg().asNum("max-tcp-per-client");

    g_fdm->addReadFD(s_rcc.d_fd, handleRCC); // control channel
    bool listenOnTCP(true);

    for(;;) {
      while(MT->schedule()); // housekeeping, let threads do their thing
      
      if(!(counter%500)) {
	MT->makeThread(houseKeeping,0);
      }

      if(!(counter%11)) {
	typedef vector<pair<int, boost::any> > expired_t;
	expired_t expired=g_fdm->getTimeouts(g_now);
	
	for(expired_t::iterator i=expired.begin() ; i != expired.end(); ++i) {
	  TCPConnection conn=any_cast<TCPConnection>(i->second);
	  if(conn.state != TCPConnection::DONE) {
	    if(g_logCommonErrors)
	      L<<Logger::Warning<<"Timeout from remote TCP client "<< conn.remote.toString() <<endl;
	    g_fdm->removeReadFD(i->first);
	    conn.closeAndCleanup();
	  }
	}
      }
      
      counter++;

      if(statsWanted) {
	doStats();
      }

      gettimeofday(&g_now, 0);
      g_fdm->run(&g_now);

      if(listenOnTCP) {
	if(TCPConnection::s_currentConnections > maxTcpClients) {  // shutdown
	  for(g_tcpListenSockets_t::iterator i=g_tcpListenSockets.begin(); i != g_tcpListenSockets.end(); ++i)
	    g_fdm->removeReadFD(*i);
	  listenOnTCP=false;
	}
      }
      else {
	if(TCPConnection::s_currentConnections <= maxTcpClients) {  // reenable
	  for(g_tcpListenSockets_t::iterator i=g_tcpListenSockets.begin(); i != g_tcpListenSockets.end(); ++i)
	    g_fdm->addReadFD(*i, handleNewTCPQuestion);
	  listenOnTCP=true;
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
