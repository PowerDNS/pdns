/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2010  PowerDNS.COM BV

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

#ifndef WIN32
# include <netdb.h>
# include <sys/stat.h>
# include <unistd.h>
#else 
 #include "ntservice.hh"
 #include "recursorservice.hh"
#endif // WIN32

#include <boost/foreach.hpp>

#include <pthread.h>
#include "recpacketcache.hh"
#include "utility.hh" 
#include "dns_random.hh"
#include <iostream>
#include <errno.h>
#include <map>
#include <set>
#include "recursor_cache.hh"
#include "cachecleaner.hh"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include "misc.hh"
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
#include <boost/algorithm/string.hpp>
#include <netinet/tcp.h>
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "zoneparser-tng.hh"
#include "rec_channel.hh"
#include "logger.hh"
#include "iputils.hh"
#include "mplexer.hh"
#include "config.h"
#include "lua-pdns-recursor.hh"

#ifndef RECURSOR
#include "statbag.hh"
StatBag S;
#endif

__thread FDMultiplexer* t_fdm;
__thread unsigned int t_id;
unsigned int g_maxTCPPerClient;
unsigned int g_networkTimeoutMsec;
bool g_logCommonErrors;
__thread shared_ptr<PowerDNSLua>* t_pdl;
__thread RemoteKeeper* t_remotes;

RecursorControlChannel s_rcc; // only active in thread 0

// for communicating with our threads
struct ThreadPipeSet
{
  int writeToThread;
  int readToThread;
  int writeFromThread;
  int readFromThread;
};

vector<ThreadPipeSet> g_pipes; // effectively readonly after startup

SyncRes::domainmap_t* g_initialDomainMap; // new threads needs this to be setup

#include "namespaces.hh"

__thread MemRecursorCache* t_RC;
__thread RecursorPacketCache* t_packetCache;
RecursorStats g_stats;
bool g_quiet;

bool g_weDistributeQueries; // if true, only 1 thread listens on the incoming query sockets

static __thread NetmaskGroup* t_allowFrom;
static NetmaskGroup* g_initialAllowFrom; // new thread needs to be setup with this

NetmaskGroup* g_dontQuery;
string s_programname="pdns_recursor";

typedef vector<int> tcpListenSockets_t;
tcpListenSockets_t g_tcpListenSockets;   // shared across threads, but this is fine, never written to from a thread. All threads listen on all sockets
int g_tcpTimeout;
unsigned int g_maxMThreads;
struct timeval g_now; // timestamp, updated (too) frequently
map<int, ComboAddress> g_listenSocketsAddresses; // is shared across all threads right now

__thread MT_t* MT; // the big MTasker

unsigned int g_numThreads;

#define LOCAL_NETS "127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fe80::/10"

//! used to send information to a newborn mthread
struct DNSComboWriter {
  DNSComboWriter(const char* data, uint16_t len, const struct timeval& now) : d_mdp(data, len), d_now(now), 
        											        d_tcp(false), d_socket(-1)
  {}
  MOADNSParser d_mdp;
  void setRemote(const ComboAddress* sa)
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
  shared_ptr<TCPConnection> d_tcpConnection;
};


ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}


void handleTCPClientWritable(int fd, FDMultiplexer::funcparam_t& var);

// -1 is error, 0 is timeout, 1 is success
int asendtcp(const string& data, Socket* sock) 
{
  PacketID pident;
  pident.sock=sock;
  pident.outMSG=data;
  
  t_fdm->addWriteFD(sock->getHandle(), handleTCPClientWritable, pident);
  string packet;

  int ret=MT->waitEvent(pident, &packet, g_networkTimeoutMsec);

  if(!ret || ret==-1) { // timeout
    t_fdm->removeWriteFD(sock->getHandle());
  }
  else if(packet.size() !=data.size()) { // main loop tells us what it sent out, or empty in case of an error
    return -1;
  }
  return ret;
}

void handleTCPClientReadable(int fd, FDMultiplexer::funcparam_t& var);

// -1 is error, 0 is timeout, 1 is success
int arecvtcp(string& data, int len, Socket* sock) 
{
  data.clear();
  PacketID pident;
  pident.sock=sock;
  pident.inNeeded=len;
  t_fdm->addReadFD(sock->getHandle(), handleTCPClientReadable, pident);

  int ret=MT->waitEvent(pident,&data, g_networkTimeoutMsec);
  if(!ret || ret==-1) { // timeout
    t_fdm->removeReadFD(sock->getHandle());
  }
  else if(data.empty()) {// error, EOF or other
    return -1;
  }

  return ret;
}

vector<ComboAddress> g_localQueryAddresses4, g_localQueryAddresses6; 
const ComboAddress g_local4("0.0.0.0"), g_local6("::");

//! pick a random query local address
ComboAddress getQueryLocalAddress(int family, uint16_t port)
{
  ComboAddress ret;
  if(family==AF_INET) {
    if(g_localQueryAddresses4.empty()) 
      ret = g_local4;
    else 
      ret = g_localQueryAddresses4[dns_random(g_localQueryAddresses4.size())];
    ret.sin4.sin_port = htons(port);
  }
  else {
    if(g_localQueryAddresses6.empty())
      ret = g_local6;
    else
      ret = g_localQueryAddresses6[dns_random(g_localQueryAddresses6.size())];
      
    ret.sin6.sin6_port = htons(port);
  }
  return ret;
}

void handleUDPServerResponse(int fd, FDMultiplexer::funcparam_t&);

void setSocketBuffer(int fd, int optname, uint32_t size)
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


static void setSocketReceiveBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_RCVBUF, size);
}

static void setSocketSendBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_SNDBUF, size);
}


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

  typedef set<int> socks_t;
  socks_t d_socks;

  // returning -1 means: temporary OS error (ie, out of files), -2 means OS error
  int getSocket(const ComboAddress& toaddr, int* fd)
  {
    *fd=makeClientSocket(toaddr.sin4.sin_family);
    if(*fd < 0) // temporary error - receive exception otherwise
      return -1;

    if(connect(*fd, (struct sockaddr*)(&toaddr), toaddr.getSocklen()) < 0) {
      int err = errno;
      //      returnSocket(*fd);
      Utility::closesocket(*fd);
      if(err==ENETUNREACH) // Seth "My Interfaces Are Like A Yo Yo" Arnold special
        return -2;
      return -1;
    }

    d_socks.insert(*fd);
    d_numsocks++;
    return 0;
  }

  void returnSocket(int fd)
  {
    socks_t::iterator i=d_socks.find(fd);
    if(i==d_socks.end()) {
      throw AhuException("Trying to return a socket (fd="+lexical_cast<string>(fd)+") not in the pool");
    }
    returnSocketLocked(i);
  }

  // return a socket to the pool, or simply erase it
  void returnSocketLocked(socks_t::iterator& i)
  {
    if(i==d_socks.end()) {
      throw AhuException("Trying to return a socket not in the pool");
    }
    try {
      t_fdm->removeReadFD(*i);
    }
    catch(FDMultiplexerException& e) {
      // we sometimes return a socket that has not yet been assigned to t_fdm
    }
    Utility::closesocket(*i);
    
    d_socks.erase(i++);
    --d_numsocks;
  }

  // returns -1 for errors which might go away, throws for ones that won't
  static int makeClientSocket(int family)
  {
    int ret=(int)socket(family, SOCK_DGRAM, 0);
    if(ret < 0 && errno==EMFILE) // this is not a catastrophic error
      return ret;
    
    if(ret<0) 
      throw AhuException("Making a socket for resolver: "+stringerror());

    
    int tries=10;
    while(--tries) {
      uint16_t port;
      
      if(tries==1)  // fall back to kernel 'random'
        port = 0;
      else
        port = 1025 + dns_random(64510);
      
      ComboAddress sin=getQueryLocalAddress(family, port); // does htons for us

      if (::bind(ret, (struct sockaddr *)&sin, sin.getSocklen()) >= 0) 
        break;
    }
    if(!tries)
      throw AhuException("Resolver binding to local query client socket: "+stringerror());
    
    Utility::setNonBlocking(ret);
    return ret;
  }
};

static __thread UDPClientSocks* t_udpclientsocks;

/* these two functions are used by LWRes */
// -2 is OS error, -1 is error that depends on the remote, > 0 is success
int asendto(const char *data, int len, int flags, 
            const ComboAddress& toaddr, uint16_t id, const string& domain, uint16_t qtype, int* fd) 
{

  PacketID pident;
  pident.domain = domain;
  pident.remote = toaddr;
  pident.type = qtype;

  // see if there is an existing outstanding request we can chain on to, using partial equivalence function
  pair<MT_t::waiters_t::iterator, MT_t::waiters_t::iterator> chain=MT->d_waiters.equal_range(pident, PacketIDBirthdayCompare());

  for(; chain.first != chain.second; chain.first++) {
    if(chain.first->key.fd > -1) { // don't chain onto existing chained waiter!
      /*
      cerr<<"Orig: "<<pident.domain<<", "<<pident.remote.toString()<<", id="<<id<<endl;
      cerr<<"Had hit: "<< chain.first->key.domain<<", "<<chain.first->key.remote.toString()<<", id="<<chain.first->key.id
          <<", count="<<chain.first->key.chain.size()<<", origfd: "<<chain.first->key.fd<<endl;
      */
      chain.first->key.chain.insert(id); // we can chain
      *fd=-1;                            // gets used in waitEvent / sendEvent later on
      return 1;
    }
  }

  int ret=t_udpclientsocks->getSocket(toaddr, fd);
  if(ret < 0)
    return ret;

  pident.fd=*fd;
  pident.id=id;
  
  t_fdm->addReadFD(*fd, handleUDPServerResponse, pident);
  ret = send(*fd, data, len, 0);

  int tmp = errno;

  if(ret < 0)
    t_udpclientsocks->returnSocket(*fd);

  errno = tmp; // this is for logging purposes only
  return ret;
}

// -1 is error, 0 is timeout, 1 is success
int arecvfrom(char *data, int len, int flags, const ComboAddress& fromaddr, int *d_len, 
              uint16_t id, const string& domain, uint16_t qtype, int fd, struct timeval* now)
{
  static optional<unsigned int> nearMissLimit;
  if(!nearMissLimit) 
    nearMissLimit=::arg().asNum("spoof-nearmiss-max");

  PacketID pident;
  pident.fd=fd;
  pident.id=id;
  pident.domain=domain;
  pident.type = qtype;
  pident.remote=fromaddr;

  string packet;
  int ret=MT->waitEvent(pident, &packet, g_networkTimeoutMsec, now);

  if(ret > 0) {
    if(packet.empty()) // means "error"
      return -1; 

    *d_len=(int)packet.size();
    memcpy(data,packet.c_str(),min(len,*d_len));
    if(*nearMissLimit && pident.nearMisses > *nearMissLimit) {
      L<<Logger::Error<<"Too many ("<<pident.nearMisses<<" > "<<*nearMissLimit<<") bogus answers for '"<<domain<<"' from "<<fromaddr.toString()<<", assuming spoof attempt."<<endl;
      g_stats.spoofCount++;
      return -1;
    }
  }
  else {
    if(fd >= 0)
      t_udpclientsocks->returnSocket(fd);
  }
  return ret;
}


string s_pidfname;
static void writePid(void)
{
  ofstream of(s_pidfname.c_str(), ios_base::app);
  if(of)
    of<< Utility::getpid() <<endl;
  else
    L<<Logger::Error<<"Requested to write pid for "<<Utility::getpid()<<" to "<<s_pidfname<<" failed: "<<strerror(errno)<<endl;
}

typedef map<ComboAddress, uint32_t, ComboAddress::addressOnlyLessThan> tcpClientCounts_t;
tcpClientCounts_t __thread* t_tcpClientCounts;


TCPConnection::TCPConnection(int fd, const ComboAddress& addr) : d_remote(addr), d_fd(fd)
{ 
  ++s_currentConnections; 
  (*t_tcpClientCounts)[d_remote]++;
}

TCPConnection::~TCPConnection()
{
  if(Utility::closesocket(d_fd) < 0) 
    unixDie("closing socket for TCPConnection");
  if(t_tcpClientCounts->count(d_remote) && !(*t_tcpClientCounts)[d_remote]--) 
    t_tcpClientCounts->erase(d_remote);
  --s_currentConnections;
}

AtomicCounter TCPConnection::s_currentConnections; 
void handleRunningTCPQuestion(int fd, FDMultiplexer::funcparam_t& var);

void updateRcodeStats(int res)
{
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
}

void startDoResolve(void *p)
{
  DNSComboWriter* dc=(DNSComboWriter *)p;

  try {
    uint16_t maxudpsize=512;
    EDNSOpts edo;
    if(getEDNSOpts(dc->d_mdp, &edo)) {
      maxudpsize=max(edo.d_packetsize, (uint16_t)1280);
    }
    
    vector<DNSResourceRecord> ret;
    vector<uint8_t> packet;

    DNSPacketWriter pw(packet, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_mdp.d_qclass); 

    pw.getHeader()->aa=0;
    pw.getHeader()->ra=1;
    pw.getHeader()->qr=1;
    pw.getHeader()->tc=0;
    pw.getHeader()->id=dc->d_mdp.d_header.id;
    pw.getHeader()->rd=dc->d_mdp.d_header.rd;

    SyncRes sr(dc->d_now);
    if(!g_quiet)
      L<<Logger::Error<<t_id<<" ["<<MT->getTid()<<"] " << (dc->d_tcp ? "TCP " : "") << "question for '"<<dc->d_mdp.d_qname<<"|"
       <<DNSRecordContent::NumberToType(dc->d_mdp.d_qtype)<<"' from "<<dc->getRemote()<<endl;

    sr.setId(MT->getTid());
    if(!dc->d_mdp.d_header.rd)
      sr.setCacheOnly();

    int res;

    bool variableAnswer = false;
    // if there is a PowerDNSLua active, and it 'took' the query in preResolve, we don't launch beginResolve
    if(!t_pdl->get() || !(*t_pdl)->preresolve(dc->d_remote, g_listenSocketsAddresses[dc->d_socket], dc->d_mdp.d_qname, QType(dc->d_mdp.d_qtype), ret, res, &variableAnswer)) {
       res = sr.beginResolve(dc->d_mdp.d_qname, QType(dc->d_mdp.d_qtype), dc->d_mdp.d_qclass, ret);

      if(t_pdl->get()) {
        if(res == RCode::NXDomain)
          (*t_pdl)->nxdomain(dc->d_remote, g_listenSocketsAddresses[dc->d_socket], dc->d_mdp.d_qname, QType(dc->d_mdp.d_qtype), ret, res, &variableAnswer);
      }
    }
    
    uint32_t minTTL=numeric_limits<uint32_t>::max();
    if(res<0) {
      pw.getHeader()->rcode=RCode::ServFail;
      // no commit here, because no record
      g_stats.servFails++;
    }
    else {
      pw.getHeader()->rcode=res;
      updateRcodeStats(res);
    
      if(ret.size()) {
        shuffle(ret);
        
        for(vector<DNSResourceRecord>::const_iterator i=ret.begin(); i!=ret.end(); ++i) {
          pw.startRecord(i->qname, i->qtype.getCode(), i->ttl, i->qclass, (DNSPacketWriter::Place)i->d_place); 
          minTTL = min(minTTL, i->ttl);
          if(i->qtype.getCode() == QType::A) { // blast out A record w/o doing whole dnswriter thing
            uint32_t ip=0;
            IpToU32(i->content, &ip);
            pw.xfr32BitInt(htonl(ip));
          } else {
            shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(i->qtype.getCode(), i->qclass, i->content)); 
            drc->toPacket(pw);
          }
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
      sendto(dc->d_socket, (const char*)&*packet.begin(), packet.size(), 0, (struct sockaddr *)(&dc->d_remote), dc->d_remote.getSocklen());
      if(!SyncRes::s_nopacketcache && !variableAnswer ) {
        t_packetCache->insertResponsePacket(string((const char*)&*packet.begin(), packet.size()), g_now.tv_sec, 
        				   min(minTTL, 
        				       (pw.getHeader()->rcode == RCode::ServFail) ? SyncRes::s_packetcacheservfailttl : SyncRes::s_packetcachettl
        				       ) 
        				  );
      }
    }
    else {
      char buf[2];
      buf[0]=packet.size()/256;
      buf[1]=packet.size()%256;

      Utility::iovec iov[2];

      iov[0].iov_base=(void*)buf;              iov[0].iov_len=2;
      iov[1].iov_base=(void*)&*packet.begin(); iov[1].iov_len = packet.size();

      int ret=Utility::writev(dc->d_socket, iov, 2);
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
        // no need to remove us from FDM, we weren't there
        dc->d_socket = -1;
      }
      else {
        dc->d_tcpConnection->state=TCPConnection::BYTE0;
        Utility::gettimeofday(&g_now, 0); // needs to be updated
        t_fdm->addReadFD(dc->d_socket, handleRunningTCPQuestion, dc->d_tcpConnection);
        t_fdm->setReadTTD(dc->d_socket, g_now, g_tcpTimeout);
      }
    }
    
    if(!g_quiet) {
      L<<Logger::Error<<t_id<<" ["<<MT->getTid()<<"] answer to "<<(dc->d_mdp.d_header.rd?"":"non-rd ")<<"question '"<<dc->d_mdp.d_qname<<"|"<<DNSRecordContent::NumberToType(dc->d_mdp.d_qtype);
      L<<"': "<<ntohs(pw.getHeader()->ancount)<<" answers, "<<ntohs(pw.getHeader()->arcount)<<" additional, took "<<sr.d_outqueries<<" packets, "<<
      sr.d_throttledqueries<<" throttled, "<<sr.d_timeouts<<" timeouts, "<<sr.d_tcpoutqueries<<" tcp connections, rcode="<<res<<endl;
    }

    sr.d_outqueries ? t_RC->cacheMisses++ : t_RC->cacheHits++; 
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
    dc=0;
  }
  catch(AhuException &ae) {
    L<<Logger::Error<<"startDoResolve problem: "<<ae.reason<<endl;
    delete dc;
  }
  catch(MOADNSException& e) {
    L<<Logger::Error<<"DNS parser error: "<<dc->d_mdp.d_qname<<", "<<e.what()<<endl;
    delete dc;
  }
  catch(std::exception& e) {
    L<<Logger::Error<<"STL error: "<<e.what()<<endl;
    delete dc;
  }
  catch(...) {
    L<<Logger::Error<<"Any other exception in a resolver context"<<endl;
  }
}

void makeControlChannelSocket()
{
  string sockname=::arg()["socket-dir"]+"/pdns_recursor.controlsocket";
  s_rcc.listen(sockname);
  
#ifndef WIN32
  int sockowner = -1;
  int sockgroup = -1;

  if (!::arg().isEmpty("socket-group"))
    sockgroup=::arg().asGid("socket-group");
  if (!::arg().isEmpty("socket-owner"))
    sockowner=::arg().asUid("socket-owner");
  
  if (sockgroup > -1 || sockowner > -1) {
    if(chown(sockname.c_str(), sockowner, sockgroup) < 0) {
      unixDie("Failed to chown control socket");
    }
  }

  // do mode change if socket-mode is given
  if(!::arg().isEmpty("socket-mode")) {
    mode_t sockmode=::arg().asMode("socket-mode");
    chmod(sockname.c_str(), sockmode);
  }
#endif
}

void handleRunningTCPQuestion(int fd, FDMultiplexer::funcparam_t& var)
{
  shared_ptr<TCPConnection> conn=any_cast<shared_ptr<TCPConnection> >(var);

  if(conn->state==TCPConnection::BYTE0) {
    int bytes=recv(conn->getFD(), conn->data, 2, 0);
    if(bytes==1)
      conn->state=TCPConnection::BYTE1;
    if(bytes==2) { 
      conn->qlen=(((unsigned char)conn->data[0]) << 8)+ (unsigned char)conn->data[1];
      conn->bytesread=0;
      conn->state=TCPConnection::GETQUESTION;
    }
    if(!bytes || bytes < 0) {
      t_fdm->removeReadFD(fd);
      return;
    }
  }
  else if(conn->state==TCPConnection::BYTE1) {
    int bytes=recv(conn->getFD(), conn->data+1, 1, 0);
    if(bytes==1) {
      conn->state=TCPConnection::GETQUESTION;
      conn->qlen=(((unsigned char)conn->data[0]) << 8)+ (unsigned char)conn->data[1];
      conn->bytesread=0;
    }
    if(!bytes || bytes < 0) {
      if(g_logCommonErrors)
        L<<Logger::Error<<"TCP client "<< conn->d_remote.toString() <<" disconnected after first byte"<<endl;
      t_fdm->removeReadFD(fd);
      return;
    }
  }
  else if(conn->state==TCPConnection::GETQUESTION) {
    int bytes=recv(conn->getFD(), conn->data + conn->bytesread, conn->qlen - conn->bytesread, 0);
    if(!bytes || bytes < 0) {
      L<<Logger::Error<<"TCP client "<< conn->d_remote.toString() <<" disconnected while reading question body"<<endl;
      t_fdm->removeReadFD(fd);
      return;
    }
    conn->bytesread+=bytes;
    if(conn->bytesread==conn->qlen) {
      t_fdm->removeReadFD(fd); // should no longer awake ourselves when there is data to read

      DNSComboWriter* dc=0;
      try {
        dc=new DNSComboWriter(conn->data, conn->qlen, g_now);
      }
      catch(MOADNSException &mde) {
        g_stats.clientParseError++; 
        if(g_logCommonErrors)
          L<<Logger::Error<<"Unable to parse packet from TCP client "<< conn->d_remote.toString() <<endl;
        return;
      }
      dc->d_tcpConnection = conn; // carry the torch
      dc->setSocket(conn->getFD()); // this is the only time a copy is made of the actual fd
      dc->d_tcp=true;
      dc->setRemote(&conn->d_remote);
      if(dc->d_mdp.d_header.qr) {
        delete dc;
        L<<Logger::Error<<"Ignoring answer on server socket!"<<endl;
        return;
      }
      else {
        ++g_stats.qcounter;
        ++g_stats.tcpqcounter;
        MT->makeThread(startDoResolve, dc); // deletes dc, will set state to BYTE0 again
        return;
      }
    }
  }
}

//! Handle new incoming TCP connection
void handleNewTCPQuestion(int fd, FDMultiplexer::funcparam_t& )
{
  ComboAddress addr;
  socklen_t addrlen=sizeof(addr);
  int newsock=(int)accept(fd, (struct sockaddr*)&addr, &addrlen);
  if(newsock>0) {
    if(MT->numProcesses() > g_maxMThreads) {
      g_stats.overCapacityDrops++;
      Utility::closesocket(newsock);
      return;
    }

    t_remotes->addRemote(addr);
    if(t_allowFrom && !t_allowFrom->match(&addr)) {
      if(!g_quiet) 
        L<<Logger::Error<<"["<<MT->getTid()<<"] dropping TCP query from "<<addr.toString()<<", address not matched by allow-from"<<endl;

      g_stats.unauthorizedTCP++;
      Utility::closesocket(newsock);
      return;
    }
    if(g_maxTCPPerClient && t_tcpClientCounts->count(addr) && (*t_tcpClientCounts)[addr] >= g_maxTCPPerClient) {
      g_stats.tcpClientOverflow++;
      Utility::closesocket(newsock); // don't call TCPConnection::closeAndCleanup here - did not enter it in the counts yet!
      return;
    }
    
    Utility::setNonBlocking(newsock);
    shared_ptr<TCPConnection> tc(new TCPConnection(newsock, addr));
    tc->state=TCPConnection::BYTE0;
    
    t_fdm->addReadFD(tc->getFD(), handleRunningTCPQuestion, tc);

    struct timeval now;
    Utility::gettimeofday(&now, 0);
    t_fdm->setReadTTD(tc->getFD(), now, g_tcpTimeout);
  }
}
 
string* doProcessUDPQuestion(const std::string& question, const ComboAddress& fromaddr, int fd)
{
  ++g_stats.qcounter;

  string response;
  try {
    uint32_t age;
    if(!SyncRes::s_nopacketcache && t_packetCache->getResponsePacket(question, g_now.tv_sec, &response, &age)) {
      if(!g_quiet)
	L<<Logger::Error<<t_id<< " question answered from packet cache from "<<fromaddr.toString()<<endl;

      g_stats.packetCacheHits++;
      SyncRes::s_queries++;
      ageDNSPacket(response, age);
      sendto(fd, response.c_str(), response.length(), 0, (struct sockaddr*) &fromaddr, fromaddr.getSocklen());
      if(response.length() >= sizeof(struct dnsheader))
	updateRcodeStats(((struct dnsheader*)response.c_str())->rcode);
      g_stats.avgLatencyUsec=(uint64_t)((1-0.0001)*g_stats.avgLatencyUsec + 0); // we assume 0 usec
      return 0;
    }
  } 
  catch(std::exception& e) {
    L<<Logger::Error<<"Error processing or aging answer packet: "<<e.what()<<endl;
    return 0;
  }
  
  
  if(MT->numProcesses() > g_maxMThreads) {
    g_stats.overCapacityDrops++;
    return 0;
  }
  
  DNSComboWriter* dc = new DNSComboWriter(question.c_str(), question.size(), g_now);
  dc->setSocket(fd);
  dc->setRemote(&fromaddr);

  dc->d_tcp=false;
  MT->makeThread(startDoResolve, (void*) dc); // deletes dc
  return 0;
} 
 
void handleNewUDPQuestion(int fd, FDMultiplexer::funcparam_t& var)
{
  int len;
  char data[1500];
  ComboAddress fromaddr;
  socklen_t addrlen=sizeof(fromaddr);
  
  if((len=recvfrom(fd, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen)) >= 0) {
    t_remotes->addRemote(fromaddr);

    if(t_allowFrom && !t_allowFrom->match(&fromaddr)) {
      if(!g_quiet) 
        L<<Logger::Error<<"["<<MT->getTid()<<"] dropping UDP query from "<<fromaddr.toString()<<", address not matched by allow-from"<<endl;

      g_stats.unauthorizedUDP++;
      return;
    }
    try {
      dnsheader* dh=(dnsheader*)data;
      
      if(dh->qr) {
        if(g_logCommonErrors)
          L<<Logger::Error<<"Ignoring answer from "<<fromaddr.toString()<<" on server socket!"<<endl;
      }
      else {
	string question(data, len);
	if(g_weDistributeQueries)
	  distributeAsyncFunction(boost::bind(doProcessUDPQuestion, question, fromaddr, fd));
	else
	  doProcessUDPQuestion(question, fromaddr, fd);
      }
    }
    catch(MOADNSException& mde) {
      g_stats.clientParseError++; 
      if(g_logCommonErrors)
        L<<Logger::Error<<"Unable to parse packet from remote UDP client "<<fromaddr.toString() <<": "<<mde.what()<<endl;
    }
  }
  else {
    // cerr<<t_id<<" had error: "<<stringerror()<<endl;
    if(errno == EAGAIN)
      g_stats.noPacketError++;
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
  
  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    ServiceTuple st;
    st.port=::arg().asNum("local-port");
    parseService(*i, st);
    
    ComboAddress sin;

    memset((char *)&sin,0, sizeof(sin));
    sin.sin4.sin_family = AF_INET;
    if(!IpToU32(st.host, (uint32_t*)&sin.sin4.sin_addr.s_addr)) {
      sin.sin6.sin6_family = AF_INET6;
      if(makeIPv6sockaddr(st.host, &sin.sin6) < 0)
        throw AhuException("Unable to resolve local address for TCP server on '"+ st.host +"'"); 
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

    sin.sin4.sin_port = htons(st.port);
    int socklen=sin.sin4.sin_family==AF_INET ? sizeof(sin.sin4) : sizeof(sin.sin6);
    if (::bind(fd, (struct sockaddr *)&sin, socklen )<0) 
      throw AhuException("Binding TCP server socket for "+ st.host +": "+stringerror());
    
    Utility::setNonBlocking(fd);
    setSocketSendBuffer(fd, 65000);
    listen(fd, 128);
    deferredAdd.push_back(make_pair(fd, handleNewTCPQuestion));
    g_tcpListenSockets.push_back(fd);

    if(sin.sin4.sin_family == AF_INET) 
      L<<Logger::Error<<"Listening for TCP queries on "<< sin.toString() <<":"<<st.port<<endl;
    else
      L<<Logger::Error<<"Listening for TCP queries on ["<< sin.toString() <<"]:"<<st.port<<endl;
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
    ServiceTuple st;
    st.port=::arg().asNum("local-port");
    parseService(*i, st);

    ComboAddress sin;

    memset(&sin, 0, sizeof(sin));
    sin.sin4.sin_family = AF_INET;
    if(!IpToU32(st.host.c_str() , (uint32_t*)&sin.sin4.sin_addr.s_addr)) {
      sin.sin6.sin6_family = AF_INET6;
      if(makeIPv6sockaddr(st.host, &sin.sin6) < 0)
        throw AhuException("Unable to resolve local address for UDP server on '"+ st.host +"'"); 
    }
    
    int fd=socket(sin.sin4.sin_family, SOCK_DGRAM, 0);

    if(fd < 0) {
      throw AhuException("Making a UDP server socket for resolver: "+netstringerror());
    }

    setSocketReceiveBuffer(fd, 200000);
    sin.sin4.sin_port = htons(st.port);

    int socklen=sin.sin4.sin_family==AF_INET ? sizeof(sin.sin4) : sizeof(sin.sin6);
    if (::bind(fd, (struct sockaddr *)&sin, socklen)<0) 
      throw AhuException("Resolver binding to server socket on port "+ lexical_cast<string>(st.port) +" for "+ st.host+": "+stringerror());
    
    Utility::setNonBlocking(fd);

    deferredAdd.push_back(make_pair(fd, handleNewUDPQuestion));
    g_listenSocketsAddresses[fd]=sin;  // this is written to only from the startup thread, not from the workers
    if(sin.sin4.sin_family == AF_INET) 
      L<<Logger::Error<<"Listening for UDP queries on "<< sin.toString() <<":"<<st.port<<endl;
    else
      L<<Logger::Error<<"Listening for UDP queries on ["<< sin.toString() <<"]:"<<st.port<<endl;
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
  static time_t lastOutputTime;
  static uint64_t lastQueryCount;
  
  if(g_stats.qcounter && (t_RC->cacheHits + t_RC->cacheMisses) && SyncRes::s_queries && SyncRes::s_outqueries) {  // this only runs once thread 0 has had hits
    uint64_t cacheHits = broadcastAccFunction<uint64_t>(pleaseGetCacheHits);
    uint64_t cacheMisses = broadcastAccFunction<uint64_t>(pleaseGetCacheMisses);
    
    L<<Logger::Warning<<"stats: "<<g_stats.qcounter<<" questions, "<<
      broadcastAccFunction<uint64_t>(pleaseGetCacheSize)<< " cache entries, "<<
      broadcastAccFunction<uint64_t>(pleaseGetNegCacheSize)<<" negative entries, "<<
      (int)((cacheHits*100.0)/(cacheHits+cacheMisses))<<"% cache hits"<<endl; 
    
    L<<Logger::Warning<<"stats: throttle map: "
      << broadcastAccFunction<uint64_t>(pleaseGetThrottleSize) <<", ns speeds: "
      << broadcastAccFunction<uint64_t>(pleaseGetNsSpeedsSize)<<endl;  
    L<<Logger::Warning<<"stats: outpacket/query ratio "<<(int)(SyncRes::s_outqueries*100.0/SyncRes::s_queries)<<"%";
    L<<Logger::Warning<<", "<<(int)(SyncRes::s_throttledqueries*100.0/(SyncRes::s_outqueries+SyncRes::s_throttledqueries))<<"% throttled, "
     <<SyncRes::s_nodelegated<<" no-delegation drops"<<endl;
    L<<Logger::Warning<<"stats: "<<SyncRes::s_tcpoutqueries<<" outgoing tcp connections, "<<
      broadcastAccFunction<uint64_t>(pleaseGetConcurrentQueries)<<" queries running, "<<SyncRes::s_outgoingtimeouts<<" outgoing timeouts"<<endl;

    //L<<Logger::Warning<<"stats: "<<g_stats.ednsPingMatches<<" ping matches, "<<g_stats.ednsPingMismatches<<" mismatches, "<<
      //g_stats.noPingOutQueries<<" outqueries w/o ping, "<< g_stats.noEdnsOutQueries<<" w/o EDNS"<<endl;
    
    L<<Logger::Warning<<"stats: " <<  broadcastAccFunction<uint64_t>(pleaseGetPacketCacheSize) <<
    " packet cache entries, "<<(int)(100.0*broadcastAccFunction<uint64_t>(pleaseGetPacketCacheHits)/SyncRes::s_queries) << "% packet cache hits"<<endl;
    
    time_t now = time(0);
    if(lastOutputTime && lastQueryCount && now != lastOutputTime) {
      L<<Logger::Warning<<"stats: "<< (SyncRes::s_queries - lastQueryCount) / (now - lastOutputTime) <<" qps (average over "<< (now - lastOutputTime) << " seconds)"<<endl;
    }
    lastOutputTime = now;
    lastQueryCount = SyncRes::s_queries;
  }
  else if(statsWanted) 
    L<<Logger::Warning<<"stats: no stats yet!"<<endl;

  statsWanted=false;
}

static void houseKeeping(void *)
try
{
  static __thread time_t last_stat, last_rootupdate, last_prune;
  static __thread int cleanCounter=0;
  struct timeval now;
  Utility::gettimeofday(&now, 0);

  // clog<<"* "<<t_id<<" "<<(void*)&last_stat<<"\t"<<(unsigned int)last_stat<<endl;

  if(now.tv_sec - last_prune > (time_t)(5 + t_id)) { 
    DTime dt;
    dt.setTimeval(now);
    t_RC->doPrune(); // this function is local to a thread, so fine anyhow
    t_packetCache->doPruneTo(::arg().asNum("max-packetcache-entries") / g_numThreads);
    
    pruneCollection(t_sstorage->negcache, ::arg().asNum("max-cache-entries") / (g_numThreads * 10), 200);
    
    if(!((cleanCounter++)%40)) {  // this is a full scan!
      time_t limit=now.tv_sec-300;
      for(SyncRes::nsspeeds_t::iterator i = t_sstorage->nsSpeeds.begin() ; i!= t_sstorage->nsSpeeds.end(); )
        if(i->second.stale(limit))
          t_sstorage->nsSpeeds.erase(i++);
        else
          ++i;
    }
//    L<<Logger::Warning<<"Spent "<<dt.udiff()/1000<<" msec cleaning"<<endl;
    last_prune=time(0);
  }
  
  if(!t_id) {
    if(now.tv_sec - last_stat > 1800) { 
      doStats();
      last_stat=time(0);
    }
  }
  
  if(now.tv_sec - last_rootupdate > 7200) {
    SyncRes sr(now);
    sr.setDoEDNS0(true);
    vector<DNSResourceRecord> ret;

    sr.setNoCache();
    int res=sr.beginResolve(".", QType(QType::NS), 1, ret);
    if(!res) {
      L<<Logger::Warning<<"Refreshed . records"<<endl;
      last_rootupdate=now.tv_sec;
    }
    else
      L<<Logger::Error<<"Failed to update . records, RCODE="<<res<<endl;
  }
}
catch(AhuException& ae)
{
  L<<Logger::Error<<"Fatal error: "<<ae.reason<<endl;
  throw;
}
;

void makeThreadPipes()
{
  for(unsigned int n=0; n < g_numThreads; ++n) {
    struct ThreadPipeSet tps;
    int fd[2];
    if(pipe(fd) < 0)
      unixDie("Creating pipe for inter-thread communications");
    
    tps.readToThread = fd[0];
    tps.writeToThread = fd[1];
    
    if(pipe(fd) < 0)
      unixDie("Creating pipe for inter-thread communications");
    tps.readFromThread = fd[0];
    tps.writeFromThread = fd[1];
    
    g_pipes.push_back(tps);
  }
}

struct ThreadMSG
{
  pipefunc_t func;
  bool wantAnswer;
};

void broadcastFunction(const pipefunc_t& func, bool skipSelf)
{
  unsigned int n = 0;
  BOOST_FOREACH(ThreadPipeSet& tps, g_pipes) 
  {
    if(n++ == t_id) {
      if(!skipSelf)
        func(); // don't write to ourselves!
      continue;
    }
  
    ThreadMSG* tmsg = new ThreadMSG();
    tmsg->func = func;
    tmsg->wantAnswer = true;
    if(write(tps.writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg))
      unixDie("write to thread pipe returned wrong size or error");
    
    string* resp;
    if(read(tps.readFromThread, &resp, sizeof(resp)) != sizeof(resp))
      unixDie("read from thread pipe returned wrong size or error");
    
    if(resp) {
//      cerr <<"got response: " << *resp << endl;
      delete resp;
    }
  }
}
void distributeAsyncFunction(const pipefunc_t& func)
{
  static unsigned int counter;
  unsigned int target = 1 + (++counter % (g_pipes.size()-1));
  // cerr<<"Sending to: "<<target<<endl;
  if(target == t_id) {
    func();
    return;
  }
  ThreadPipeSet& tps = g_pipes[target];    
  ThreadMSG* tmsg = new ThreadMSG();
  tmsg->func = func;
  tmsg->wantAnswer = false;
  
  if(write(tps.writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg))
    unixDie("write to thread pipe returned wrong size or error");
    
}

void handlePipeRequest(int fd, FDMultiplexer::funcparam_t& var)
{
  ThreadMSG* tmsg;
  
  if(read(fd, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) { // fd == readToThread 
    unixDie("read from thread pipe returned wrong size or error");
  }
  
  void *resp = tmsg->func();
  if(tmsg->wantAnswer)
    if(write(g_pipes[t_id].writeFromThread, &resp, sizeof(resp)) != sizeof(resp))
      unixDie("write to thread pipe returned wrong size or error");
  
  delete tmsg;
}

template<class T> void *voider(const boost::function<T*()>& func)
{
  return func();
}

vector<ComboAddress>& operator+=(vector<ComboAddress>&a, const vector<ComboAddress>& b)
{
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

template<class T> T broadcastAccFunction(const boost::function<T*()>& func, bool skipSelf)
{
  unsigned int n = 0;
  T ret=T();
  BOOST_FOREACH(ThreadPipeSet& tps, g_pipes) 
  {
    if(n++ == t_id) {
      if(!skipSelf) {
        T* resp = (T*)func(); // don't write to ourselves!
        if(resp) {
          //~ cerr <<"got direct: " << *resp << endl;
          ret += *resp;
          delete resp;
        }
      }
      continue;
    }
      
    ThreadMSG* tmsg = new ThreadMSG();
    tmsg->func = boost::bind(voider<T>, func);
    tmsg->wantAnswer = true;
  
    if(write(tps.writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg))
      unixDie("write to thread pipe returned wrong size or error");
  
    
    T* resp;
    if(read(tps.readFromThread, &resp, sizeof(resp)) != sizeof(resp))
      unixDie("read from thread pipe returned wrong size or error");
    
    if(resp) {
      //~ cerr <<"got response: " << *resp << endl;
      ret += *resp;
      delete resp;
    }
  }
  return ret;
}

template string broadcastAccFunction(const boost::function<string*()>& fun, bool skipSelf); // explicit instantiation
template uint64_t broadcastAccFunction(const boost::function<uint64_t*()>& fun, bool skipSelf); // explicit instantiation
template vector<ComboAddress> broadcastAccFunction(const boost::function<vector<ComboAddress> *()>& fun, bool skipSelf); // explicit instantiation

void handleRCC(int fd, FDMultiplexer::funcparam_t& var)
{
  string remote;
  string msg=s_rcc.recv(&remote);
  RecursorControlParser rcp;
  RecursorControlParser::func_t* command;
  string answer=rcp.getAnswer(msg, &command);
  try {
    s_rcc.send(answer, &remote);
    command();
  }
  catch(std::exception& e) {
    L<<Logger::Error<<"Error dealing with control socket request: "<<e.what()<<endl;
  }
  catch(AhuException& ae) {
    L<<Logger::Error<<"Error dealing with control socket request: "<<ae.reason<<endl;
  }
}

void handleTCPClientReadable(int fd, FDMultiplexer::funcparam_t& var)
{
  PacketID* pident=any_cast<PacketID>(&var);
  //  cerr<<"handleTCPClientReadable called for fd "<<fd<<", pident->inNeeded: "<<pident->inNeeded<<", "<<pident->sock->getHandle()<<endl;

  shared_array<char> buffer(new char[pident->inNeeded]);

  int ret=recv(fd, buffer.get(), pident->inNeeded,0);
  if(ret > 0) {
    pident->inMSG.append(&buffer[0], &buffer[ret]);
    pident->inNeeded-=ret;
    if(!pident->inNeeded) {
      //      cerr<<"Got entire load of "<<pident->inMSG.size()<<" bytes"<<endl;
      PacketID pid=*pident;
      string msg=pident->inMSG;
      
      t_fdm->removeReadFD(fd);
      MT->sendEvent(pid, &msg); 
    }
    else {
      //      cerr<<"Still have "<<pident->inNeeded<<" left to go"<<endl;
    }
  }
  else {
    PacketID tmp=*pident;
    t_fdm->removeReadFD(fd); // pident might now be invalid (it isn't, but still)
    string empty;
    MT->sendEvent(tmp, &empty); // this conveys error status
  }
}

void handleTCPClientWritable(int fd, FDMultiplexer::funcparam_t& var)
{
  PacketID* pid=any_cast<PacketID>(&var);
  int ret=send(fd, pid->outMSG.c_str() + pid->outPos, pid->outMSG.size() - pid->outPos,0);
  if(ret > 0) {
    pid->outPos+=ret;
    if(pid->outPos==pid->outMSG.size()) {
      PacketID tmp=*pid;
      t_fdm->removeWriteFD(fd);
      MT->sendEvent(tmp, &tmp.outMSG);  // send back what we sent to convey everything is ok
    }
  }
  else {  // error or EOF
    PacketID tmp(*pid);
    t_fdm->removeWriteFD(fd);
    string sent;
    MT->sendEvent(tmp, &sent);         // we convey error status by sending empty string
  }
}

// resend event to everybody chained onto it
void doResends(MT_t::waiters_t::iterator& iter, PacketID resend, const string& content)
{
  if(iter->key.chain.empty())
    return;
  //  cerr<<"doResends called!\n";
  for(PacketID::chain_t::iterator i=iter->key.chain.begin(); i != iter->key.chain.end() ; ++i) {
    resend.fd=-1;
    resend.id=*i;
    //    cerr<<"\tResending "<<content.size()<<" bytes for fd="<<resend.fd<<" and id="<<resend.id<<endl;

    MT->sendEvent(resend, &content);
    g_stats.chainResends++;
  }
}

void handleUDPServerResponse(int fd, FDMultiplexer::funcparam_t& var)
{
  PacketID pid=any_cast<PacketID>(var);
  int len;
  char data[1500];
  ComboAddress fromaddr;
  socklen_t addrlen=sizeof(fromaddr);

  len=recvfrom(fd, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);

  if(len < (int)sizeof(dnsheader)) {
    if(len < 0)
      ; //      cerr<<"Error on fd "<<fd<<": "<<stringerror()<<"\n";
    else {
      g_stats.serverParseError++; 
      if(g_logCommonErrors)
        L<<Logger::Error<<"Unable to parse packet from remote UDP server "<< sockAddrToString((struct sockaddr_in*) &fromaddr) <<
          ": packet smalller than DNS header"<<endl;
    }

    t_udpclientsocks->returnSocket(fd);
    string empty;

    MT_t::waiters_t::iterator iter=MT->d_waiters.find(pid);
    if(iter != MT->d_waiters.end()) 
      doResends(iter, pid, empty);
    
    MT->sendEvent(pid, &empty); // this denotes error (does lookup again.. at least L1 will be hot)
    return;
  }  

  dnsheader dh;
  memcpy(&dh, data, sizeof(dh));
  
  if(dh.qr) {
    PacketID pident;
    pident.remote=fromaddr;
    pident.id=dh.id;
    pident.fd=fd;
    if(!dh.qdcount) { // UPC, Nominum, very old BIND on FormErr, NSD
      pident.domain.clear();
      pident.type = 0;
    }
    else {
      try {
        pident.domain=questionExpand(data, len, pident.type); // don't copy this from above - we need to do the actual read
      }
      catch(std::exception& e) {
        g_stats.serverParseError++; // won't be fed to lwres.cc, so we have to increment
        L<<Logger::Warning<<"Error in packet from "<<sockAddrToString((struct sockaddr_in*) &fromaddr) << ": "<<e.what() << endl;
        return;
      }
    }
    string packet;
    packet.assign(data, len);

    MT_t::waiters_t::iterator iter=MT->d_waiters.find(pident);
    if(iter != MT->d_waiters.end()) {
      doResends(iter, pident, packet);
    }

  retryWithName:

    if(!MT->sendEvent(pident, &packet)) {
      // we do a full scan for outstanding queries on unexpected answers. not too bad since we only accept them on the right port number, which is hard enough to guess
      for(MT_t::waiters_t::iterator mthread=MT->d_waiters.begin(); mthread!=MT->d_waiters.end(); ++mthread) {
        if(pident.fd==mthread->key.fd && mthread->key.remote==pident.remote &&  mthread->key.type == pident.type &&
           pdns_iequals(pident.domain, mthread->key.domain)) {
          mthread->key.nearMisses++;
        }

        // be a bit paranoid here since we're weakening our matching
        if(pident.domain.empty() && !mthread->key.domain.empty() && !pident.type && mthread->key.type && 
           pident.id  == mthread->key.id && mthread->key.remote == pident.remote) {
          // cerr<<"Empty response, rest matches though, sending to a waiter"<<endl;
          pident.domain = mthread->key.domain;
          pident.type = mthread->key.type;
          goto retryWithName; // note that this only passes on an error, lwres will still reject the packet
        }
      }
      g_stats.unexpectedCount++; // if we made it here, it really is an unexpected answer
      if(g_logCommonErrors)
        L<<Logger::Warning<<"Discarding unexpected packet from "<<fromaddr.toStringWithPort()<<": "<<pident.domain<<", "<<pident.type<<endl;
    }
    else if(fd >= 0) {
      t_udpclientsocks->returnSocket(fd);
    }
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
      return ret;
    }
    catch(FDMultiplexerException &fe) {
      L<<Logger::Error<<"Non-fatal error initializing possible multiplexer ("<<fe.what()<<"), falling back"<<endl;
    }
    catch(...) {
      L<<Logger::Error<<"Non-fatal error initializing possible multiplexer"<<endl;
    }
  }
  L<<Logger::Error<<"No working multiplexer found!"<<endl;
  exit(1);
}

  
void* doReloadLuaScript()
{
  string fname= ::arg()["lua-dns-script"];
  try {
    if(fname.empty()) {
      t_pdl->reset();
      L<<Logger::Error<<t_id<<" Unloaded current lua script"<<endl;
    }
    else {
      *t_pdl = shared_ptr<PowerDNSLua>(new PowerDNSLua(fname));
    }
  }
  catch(std::exception& e) {
    L<<Logger::Error<<t_id<<" Retaining current script, error from '"<<fname<<"': "<< e.what() <<endl;
  }
    
  L<<Logger::Warning<<t_id<<" (Re)loaded lua script from '"<<fname<<"'"<<endl;
  return 0;
}

string doQueueReloadLuaScript(vector<string>::const_iterator begin, vector<string>::const_iterator end)
{
  if(begin != end) 
    ::arg().set("lua-dns-script") = *begin;
  
  broadcastFunction(doReloadLuaScript);
  
  return "ok, reload/unload queued\n";
}  

void* recursorThread(void*);

void* pleaseSupplantACLs(NetmaskGroup *ng)
{
  t_allowFrom = ng;
  return 0;
}

void parseACLs()
{
  static bool l_initialized;
  
  if(l_initialized) { // only reload configuration file on second call
    string configname=::arg()["config-dir"]+"/recursor.conf";
    cleanSlashes(configname);
    
    if(!::arg().preParseFile(configname.c_str(), "allow-from-file")) 
      L<<Logger::Warning<<"Unable to re-parse configuration file '"<<configname<<"'"<<endl;
    
    ::arg().preParseFile(configname.c_str(), "allow-from", LOCAL_NETS);
  }

  NetmaskGroup* oldAllowFrom = t_allowFrom, *allowFrom=new NetmaskGroup;
  
  if(!::arg()["allow-from-file"].empty()) {
    string line;
    ifstream ifs(::arg()["allow-from-file"].c_str());
    if(!ifs) {
      delete allowFrom; 
      throw runtime_error("Could not open '"+::arg()["allow-from-file"]+"': "+stringerror());
    }

    string::size_type pos;
    while(getline(ifs,line)) {
      pos=line.find('#');
      if(pos!=string::npos)
        line.resize(pos);
      trim(line);
      if(line.empty())
        continue;

      allowFrom->addMask(line);
    }
    L<<Logger::Warning<<"Done parsing " << allowFrom->size() <<" allow-from ranges from file '"<<::arg()["allow-from-file"]<<"' - overriding 'allow-from' setting"<<endl;
  }
  else if(!::arg()["allow-from"].empty()) {
    vector<string> ips;
    stringtok(ips, ::arg()["allow-from"], ", ");
    
    L<<Logger::Warning<<"Only allowing queries from: ";
    for(vector<string>::const_iterator i = ips.begin(); i!= ips.end(); ++i) {
      allowFrom->addMask(*i);
      if(i!=ips.begin())
        L<<Logger::Warning<<", ";
      L<<Logger::Warning<<*i;
    }
    L<<Logger::Warning<<endl;
  }
  else {
    if(::arg()["local-address"]!="127.0.0.1" && ::arg().asNum("local-port")==53) 
      L<<Logger::Error<<"WARNING: Allowing queries from all IP addresses - this can be a security risk!"<<endl;
    delete allowFrom;
    allowFrom = 0;
  }
  
  g_initialAllowFrom = allowFrom;
  broadcastFunction(boost::bind(pleaseSupplantACLs, allowFrom));
  delete oldAllowFrom;
  
  l_initialized = true;
}

int serviceMain(int argc, char*argv[])
{
  L.setName("pdns_recursor");

  L.setLoglevel((Logger::Urgency)(6)); // info and up

  if(!::arg()["logging-facility"].empty()) {
    boost::optional<int> val=logFacilityToLOG(::arg().asNum("logging-facility") );
    if(val)
      theL().setFacility(*val);
    else
      L<<Logger::Error<<"Unknown logging facility "<<::arg().asNum("logging-facility") <<endl;
  }

  L<<Logger::Warning<<"PowerDNS recursor "<<VERSION<<" (C) 2001-2010 PowerDNS.COM BV ("<<__DATE__", "__TIME__;
#ifdef __GNUC__
  L<<", gcc "__VERSION__;
#endif // add other compilers here
#ifdef _MSC_VER
  L<<", MSVC "<<_MSC_VER;
#endif
  L<<") starting up"<<endl;
  
  L<<Logger::Warning<<"PowerDNS comes with ABSOLUTELY NO WARRANTY. "
    "This is free software, and you are welcome to redistribute it "
    "according to the terms of the GPL version 2."<<endl;
  
  L<<Logger::Warning<<"Operating in "<<(sizeof(unsigned long)*8) <<" bits mode"<<endl;
  
  #if 0
  unsigned int maxFDs, curFDs;
  getFDLimits(curFDs, maxFDs);
  if(curFDs < 2048) 
    L<<Logger::Warning<<"Only "<<curFDs<<" file descriptors available (out of: "<<maxFDs<<"), may not be suitable for high performance"<<endl;
  #endif
  
  seedRandom(::arg()["entropy-source"]);

  parseACLs();
  
  if(!::arg()["dont-query"].empty()) {
    g_dontQuery=new NetmaskGroup;
    vector<string> ips;
    stringtok(ips, ::arg()["dont-query"], ", ");
    ips.push_back("0.0.0.0");
    ips.push_back("::");

    L<<Logger::Warning<<"Will not send queries to: ";
    for(vector<string>::const_iterator i = ips.begin(); i!= ips.end(); ++i) {
      g_dontQuery->addMask(*i);
      if(i!=ips.begin())
        L<<Logger::Warning<<", ";
      L<<Logger::Warning<<*i;
    }
    L<<Logger::Warning<<endl;
  }

  g_quiet=::arg().mustDo("quiet");
  g_weDistributeQueries = ::arg().mustDo("pdns-distributes-queries");
  if(g_weDistributeQueries) {
      L<<Logger::Warning<<"PowerDNS Recursor itself will distribute queries over threads"<<endl;
  }
  
  if(::arg().mustDo("trace")) {
    SyncRes::setLog(true);
    ::arg().set("quiet")="no";
    g_quiet=false;
  }
  
  try {
    vector<string> addrs;  
    if(!::arg()["query-local-address6"].empty()) {
      SyncRes::s_doIPv6=true;
      L<<Logger::Error<<"Enabling IPv6 transport for outgoing queries"<<endl;
      
      stringtok(addrs, ::arg()["query-local-address6"], ", ;");
      BOOST_FOREACH(const string& addr, addrs) {
        g_localQueryAddresses6.push_back(ComboAddress(addr));
      }
    }
    addrs.clear();
    stringtok(addrs, ::arg()["query-local-address"], ", ;");
    BOOST_FOREACH(const string& addr, addrs) {
      g_localQueryAddresses4.push_back(ComboAddress(addr));
    }
  }
  catch(std::exception& e) {
    L<<Logger::Error<<"Assigning local query addresses: "<<e.what();
    exit(99);
  }
  
  SyncRes::s_noEDNSPing = ::arg().mustDo("disable-edns-ping");
  SyncRes::s_noEDNS = ::arg().mustDo("disable-edns");

  SyncRes::s_nopacketcache = ::arg().mustDo("disable-packetcache");

  SyncRes::s_maxnegttl=::arg().asNum("max-negative-ttl");
  SyncRes::s_maxcachettl=::arg().asNum("max-cache-ttl");
  SyncRes::s_packetcachettl=::arg().asNum("packetcache-ttl");
  SyncRes::s_packetcacheservfailttl=::arg().asNum("packetcache-servfail-ttl");
  SyncRes::s_serverID=::arg()["server-id"];
  if(SyncRes::s_serverID.empty()) {
    char tmp[128];
    gethostname(tmp, sizeof(tmp)-1);
    SyncRes::s_serverID=tmp;
  }
  
  g_networkTimeoutMsec = ::arg().asNum("network-timeout");

  g_initialDomainMap = parseAuthAndForwards();
 
    
  g_logCommonErrors=::arg().mustDo("log-common-errors");
  
  makeUDPServerSockets();
  makeTCPServerSockets();

  for(int forks = 0; forks < ::arg().asNum("processes") - 1; ++forks) {
    if(!fork()) // we are child
      break;
  }
  
  s_pidfname=::arg()["socket-dir"]+"/"+s_programname+".pid";
  if(!s_pidfname.empty())
    unlink(s_pidfname.c_str()); // remove possible old pid file 
  
#ifndef WIN32
  if(::arg().mustDo("daemon")) {
    L<<Logger::Warning<<"Calling daemonize, going to background"<<endl;
    L.toConsole(Logger::Critical);
    daemonize();
  }
  signal(SIGUSR1,usr1Handler);
  signal(SIGUSR2,usr2Handler);
  signal(SIGPIPE,SIG_IGN);
  writePid();
#endif
  makeControlChannelSocket();
  
  int newgid=0;
  if(!::arg()["setgid"].empty())
    newgid=Utility::makeGidNumeric(::arg()["setgid"]);
  int newuid=0;
  if(!::arg()["setuid"].empty())
    newuid=Utility::makeUidNumeric(::arg()["setuid"]);

  if (!::arg()["chroot"].empty()) {
    if (chroot(::arg()["chroot"].c_str())<0 || chdir("/") < 0) {
      L<<Logger::Error<<"Unable to chroot to '"+::arg()["chroot"]+"': "<<strerror (errno)<<", exiting"<<endl;
      exit(1);
    }
  }

  Utility::dropPrivs(newuid, newgid);
  
  
  g_numThreads = ::arg().asNum("threads") + ::arg().mustDo("pdns-distributes-queries");
  
  makeThreadPipes();
  
  g_tcpTimeout=::arg().asNum("client-tcp-timeout");
  g_maxTCPPerClient=::arg().asNum("max-tcp-per-client");
  g_maxMThreads=::arg().asNum("max-mthreads");

  if(g_numThreads == 1) {
    L<<Logger::Warning<<"Operating unthreaded"<<endl;
    recursorThread(0);
  }
  else {
    pthread_t tid;
    L<<Logger::Warning<<"Launching "<< g_numThreads <<" threads"<<endl;
    for(unsigned int n=0; n < g_numThreads; ++n) {
      pthread_create(&tid, 0, recursorThread, (void*)n);
    }
    void* res;

    
    pthread_join(tid, &res);
  }
  return 0;
}

void* recursorThread(void* ptr)
try
{
  t_id=(int) (long) ptr;
  SyncRes tmp(g_now); // make sure it allocates tsstorage before we do anything, like primeHints or so..
  t_sstorage->domainmap = g_initialDomainMap;
  t_allowFrom = g_initialAllowFrom;
  t_udpclientsocks = new UDPClientSocks();
  t_tcpClientCounts = new tcpClientCounts_t();
  primeHints();
  
  t_packetCache = new RecursorPacketCache();
  
  L<<Logger::Warning<<"Done priming cache with root hints"<<endl;
    
  t_RC->d_followRFC2181=::arg().mustDo("auth-can-lower-ttl");
  t_pdl = new shared_ptr<PowerDNSLua>();
  
  try {
    if(!::arg()["lua-dns-script"].empty()) {
      *t_pdl = shared_ptr<PowerDNSLua>(new PowerDNSLua(::arg()["lua-dns-script"]));
      L<<Logger::Warning<<"Loaded 'lua' script from '"<<::arg()["lua-dns-script"]<<"'"<<endl;
    }
    
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"Failed to load 'lua' script from '"<<::arg()["lua-dns-script"]<<"': "<<e.what()<<endl;
    exit(99);
  }
  
  t_remotes = new RemoteKeeper();
  t_remotes->remotes.resize(::arg().asNum("remotes-ringbuffer-entries") / g_numThreads); 
  
  if(!t_remotes->remotes.empty())
    memset(&t_remotes->remotes[0], 0, t_remotes->remotes.size() * sizeof(RemoteKeeper::remotes_t::value_type));
  
  
  MT=new MTasker<PacketID,string>(::arg().asNum("stack-size"));
  
  PacketID pident;

  t_fdm=getMultiplexer();
  if(!t_id) 
    L<<Logger::Error<<"Enabled '"<< t_fdm->getName() << "' multiplexer"<<endl;

  t_fdm->addReadFD(g_pipes[t_id].readToThread, handlePipeRequest);

  if(!g_weDistributeQueries || !t_id)  // if we distribute queries, only t_id = 0 listens
    for(deferredAdd_t::const_iterator i=deferredAdd.begin(); i!=deferredAdd.end(); ++i) 
      t_fdm->addReadFD(i->first, i->second);
  
  if(!t_id) {
    t_fdm->addReadFD(s_rcc.d_fd, handleRCC); // control channel
  }

  unsigned int maxTcpClients=::arg().asNum("max-tcp-clients");
  
  bool listenOnTCP(true);

  counter=0; // used to periodically execute certain tasks
  for(;;) {
    while(MT->schedule(&g_now)); // MTasker letting the mthreads do their thing
      
    if(!(counter%500)) {
      MT->makeThread(houseKeeping, 0);
    }

    if(!(counter%55)) {
      typedef vector<pair<int, FDMultiplexer::funcparam_t> > expired_t;
      expired_t expired=t_fdm->getTimeouts(g_now);
        
      for(expired_t::iterator i=expired.begin() ; i != expired.end(); ++i) {
        shared_ptr<TCPConnection> conn=any_cast<shared_ptr<TCPConnection> >(i->second);
        if(g_logCommonErrors)
          L<<Logger::Warning<<"Timeout from remote TCP client "<< conn->d_remote.toString() <<endl;
        t_fdm->removeReadFD(i->first);
      }
    }
      
    counter++;

    if(!t_id && statsWanted) {
      doStats();
    }

    Utility::gettimeofday(&g_now, 0);
    t_fdm->run(&g_now);
    // 'run' updates g_now for us

    if(listenOnTCP) {
      if(TCPConnection::getCurrentConnections() > maxTcpClients) {  // shutdown, too many connections
        for(tcpListenSockets_t::iterator i=g_tcpListenSockets.begin(); i != g_tcpListenSockets.end(); ++i)
          t_fdm->removeReadFD(*i);
        listenOnTCP=false;
      }
    }
    else {
      if(TCPConnection::getCurrentConnections() <= maxTcpClients) {  // reenable
        for(tcpListenSockets_t::iterator i=g_tcpListenSockets.begin(); i != g_tcpListenSockets.end(); ++i)
          t_fdm->addReadFD(*i, handleNewTCPQuestion);
        listenOnTCP=true;
      }
    }
  }
}
catch(AhuException &ae) {
  L<<Logger::Error<<"Exception: "<<ae.reason<<endl;
  return 0;
}
catch(std::exception &e) {
   L<<Logger::Error<<"STL Exception: "<<e.what()<<endl;
   return 0;
}
catch(...) {
   L<<Logger::Error<<"any other exception in main: "<<endl;
   return 0;
}

#ifdef WIN32
void doWindowsServiceArguments(RecursorService& recursor)
{
  if(::arg().mustDo( "register-service" )) {
    if ( !recursor.registerService( "The PowerDNS Recursor.", true )) {
      cerr << "Could not register service." << endl;
      exit( 99 );
    }
    
    exit( 0 );
  }

  if ( ::arg().mustDo( "unregister-service" )) {
    recursor.unregisterService();
    exit( 0 );
  }
}
#endif


int main(int argc, char **argv) 
{
  g_stats.startupTime=time(0);
  reportBasicTypes();

  int ret = EXIT_SUCCESS;
#ifdef WIN32
  RecursorService service;
  WSADATA wsaData;
  if(WSAStartup( MAKEWORD( 2, 2 ), &wsaData )) {
    cerr<<"Unable to initialize winsock\n";
    exit(1);
  }
#endif // WIN32

  try {
    ::arg().set("stack-size","stack size per mthread")="200000";
    ::arg().set("soa-minimum-ttl","Don't change")="0";
    ::arg().set("soa-serial-offset","Don't change")="0";
    ::arg().set("no-shuffle","Don't change")="off";
    ::arg().set("aaaa-additional-processing","turn on to do AAAA additional processing (slow)")="off";
    ::arg().set("local-port","port to listen on")="53";
    ::arg().set("local-address","IP addresses to listen on, separated by spaces or commas. Also accepts ports.")="127.0.0.1";
    ::arg().set("trace","if we should output heaps of logging")="off";
    ::arg().set("daemon","Operate as a daemon")="yes";
    ::arg().set("log-common-errors","If we should log rather common errors")="yes";
    ::arg().set("chroot","switch to chroot jail")="";
    ::arg().set("setgid","If set, change group id to this gid for more security")="";
    ::arg().set("setuid","If set, change user id to this uid for more security")="";
    ::arg().set("network-timeout", "Wait this nummer of milliseconds for network i/o")="1500";
    ::arg().set("threads", "Launch this number of threads")="2";
    ::arg().set("processes", "Launch this number of processes (EXPERIMENTAL, DO NOT CHANGE)")="1";
#ifdef WIN32
    ::arg().set("quiet","Suppress logging of questions and answers")="off";
    ::arg().setSwitch( "register-service", "Register the service" )= "no";
    ::arg().setSwitch( "unregister-service", "Unregister the service" )= "no";
    ::arg().setSwitch( "ntservice", "Run as service" )= "no";
    ::arg().setSwitch( "use-ntlog", "Use the NT logging facilities" )= "yes"; 
    ::arg().setSwitch( "use-logfile", "Use a log file" )= "no"; 
    ::arg().setSwitch( "logfile", "Filename of the log file" )= "recursor.log"; 
#else
    ::arg().set("quiet","Suppress logging of questions and answers")="";
    ::arg().set("logging-facility","Facility to log messages as. 0 corresponds to local0")="";
#endif
    ::arg().set("config-dir","Location of configuration directory (recursor.conf)")=SYSCONFDIR;
#ifndef WIN32
    ::arg().set("socket-owner","Owner of socket")="";
    ::arg().set("socket-group","Group of socket")="";
    ::arg().set("socket-mode", "Permissions for socket")="";
#endif
    
    ::arg().set("socket-dir","Where the controlsocket will live")=LOCALSTATEDIR;
    ::arg().set("delegation-only","Which domains we only accept delegations from")="";
    ::arg().set("query-local-address","Source IP address for sending queries")="0.0.0.0";
    ::arg().set("query-local-address6","Source IPv6 address for sending queries")="";
    ::arg().set("client-tcp-timeout","Timeout in seconds when talking to TCP clients")="2";
    ::arg().set("max-mthreads", "Maximum number of simultaneous Mtasker threads")="2048";
    ::arg().set("max-tcp-clients","Maximum number of simultaneous TCP clients")="128";
    ::arg().set("hint-file", "If set, load root hints from this file")="";
    ::arg().set("max-cache-entries", "If set, maximum number of entries in the main cache")="1000000";
    ::arg().set("max-negative-ttl", "maximum number of seconds to keep a negative cached entry in memory")="3600";
    ::arg().set("max-cache-ttl", "maximum number of seconds to keep a cached entry in memory")="86400";
    ::arg().set("packetcache-ttl", "maximum number of seconds to keep a cached entry in packetcache")="3600";
    ::arg().set("max-packetcache-entries", "maximum number of entries to keep in the packetcache")="500000";
    ::arg().set("packetcache-servfail-ttl", "maximum number of seconds to keep a cached servfail entry in packetcache")="60";
    ::arg().set("server-id", "Returned when queried for 'server.id' TXT or NSID, defaults to hostname")="";
    ::arg().set("remotes-ringbuffer-entries", "maximum number of packets to store statistics for")="0";
    ::arg().set("version-string", "string reported on version.pdns or version.bind")="PowerDNS Recursor "VERSION" $Id$";
    ::arg().set("allow-from", "If set, only allow these comma separated netmasks to recurse")=LOCAL_NETS;
    ::arg().set("allow-from-file", "If set, load allowed netmasks from this file")="";
    ::arg().set("entropy-source", "If set, read entropy from this file")="/dev/urandom";
    ::arg().set("dont-query", "If set, do not query these netmasks for DNS data")=LOCAL_NETS; 
    ::arg().set("max-tcp-per-client", "If set, maximum number of TCP sessions per client (IP address)")="0";
    ::arg().set("spoof-nearmiss-max", "If non-zero, assume spoofing after this many near misses")="20";
    ::arg().set("single-socket", "If set, only use a single socket for outgoing queries")="off";
    ::arg().set("auth-zones", "Zones for which we have authoritative data, comma separated domain=file pairs ")="";
    ::arg().set("forward-zones", "Zones for which we forward queries, comma separated domain=ip pairs")="";
    ::arg().set("forward-zones-recurse", "Zones for which we forward queries with recursion bit, comma separated domain=ip pairs")="";
    ::arg().set("forward-zones-file", "File with (+)domain=ip pairs for forwarding")="";
    ::arg().set("export-etc-hosts", "If we should serve up contents from /etc/hosts")="off";
    ::arg().set("etc-hosts-file", "Path to 'hosts' file")="/etc/hosts";
    ::arg().set("serve-rfc1918", "If we should be authoritative for RFC 1918 private IP space")="";
    ::arg().set("auth-can-lower-ttl", "If we follow RFC 2181 to the letter, an authoritative server can lower the TTL of NS records")="off";
    ::arg().set("lua-dns-script", "Filename containing an optional 'lua' script that will be used to modify dns answers")="";
    ::arg().setSwitch( "ignore-rd-bit", "Assume each packet requires recursion, for compatability" )= "off"; 
    ::arg().setSwitch( "disable-edns-ping", "Disable EDNSPing" )= "no"; 
    ::arg().setSwitch( "disable-edns", "Disable EDNS" )= ""; 
    ::arg().setSwitch( "disable-packetcache", "Disable packetcache" )= "no"; 
    ::arg().setSwitch( "pdns-distributes-queries", "If PowerDNS itself should distribute queries over threads (EXPERIMENTAL)")="no";
    

    ::arg().setCmd("help","Provide a helpful message");
    ::arg().setCmd("version","Print version string ("VERSION")");
    ::arg().setCmd("config","Output blank configuration");
    L.toConsole(Logger::Info);
    ::arg().laxParse(argc,argv); // do a lax parse

    if(::arg().mustDo("config")) {
      cout<<::arg().configstring()<<endl;
      exit(0);
    }


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
    if(::arg().mustDo("version")) {
      cerr<<"version: "VERSION<<endl;
      exit(99);
    }

#ifndef WIN32
    serviceMain(argc, argv);
#else
    doWindowsServiceArguments(service);
        L.toNTLog();
    RecursorService::instance()->start( argc, argv, ::arg().mustDo( "ntservice" )); 
#endif

  }
  catch(AhuException &ae) {
    L<<Logger::Error<<"Exception: "<<ae.reason<<endl;
    ret=EXIT_FAILURE;
  }
  catch(std::exception &e) {
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
