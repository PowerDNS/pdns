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
#include "utility.hh"
#include "resolver.hh"
#include <pthread.h>
#include <semaphore.h>
#include <iostream>
#include <errno.h>
#include "misc.hh"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <string>
#include <vector>
#include "dnspacket.hh"
#include "dns.hh"
#include "qtype.hh"
#include "tcpreceiver.hh"
#include "ahuexception.hh"
#include "statbag.hh"
#include "arguments.hh"

void Resolver::makeUDPSocket()
{
  makeSocket(SOCK_DGRAM);
}

void Resolver::makeSocket(int type)
{
  static u_int16_t port_counter=5000;
  if(d_sock>0)
    return;

  d_sock=socket(AF_INET, type,0);
  if(d_sock<0) 
    throw AhuException("Making a socket for resolver: "+stringerror());

  struct sockaddr_in sin;
  memset((char *)&sin,0, sizeof(sin));
  
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;

  int tries=10;
  while(--tries) {
    sin.sin_port = htons(10000+(port_counter++)%10000); // should be random!
  
    if (bind(d_sock, (struct sockaddr *)&sin, sizeof(sin)) >= 0) 
      break;

  }
  if(!tries)
    throw AhuException("Resolver binding to local socket: "+stringerror());
}

Resolver::Resolver()
{
  d_sock=-1;
  d_timeout=500000;
  d_soacount=0;
  d_buf=new unsigned char[66000];
}

Resolver::~Resolver()
{
  if(d_sock>=0)
    Utility::closesocket(d_sock);
  delete[] d_buf;
}

void Resolver::timeoutReadn(char *buffer, int bytes)
{
  time_t start=time(0);
  int n=0;
  int numread;
  while(n<bytes) {
    if(waitForData(d_sock, 10-(time(0)-start))<0)
      throw ResolverException("Reading data from remote nameserver over TCP: "+stringerror());

    numread=recv(d_sock,buffer+n,bytes-n,0);
    if(numread<0)
      throw ResolverException("Reading data from remote nameserver over TCP: "+stringerror());
    if(numread==0)
      throw ResolverException("Remote nameserver closed TCP connection");
    n+=numread;
  }
}

char* Resolver::sendReceive(const string &ip, u_int16_t remotePort, const char *packet, int length, unsigned int *replen)
{
  makeTCPSocket(ip, remotePort);

  if(sendData(packet,length,d_sock)<0) 
    throw ResolverException("Unable to send packet to remote nameserver "+ip+": "+stringerror());

  int plen=getLength();
  if(plen<0)
    throw ResolverException("EOF trying to get length of answer from remote TCP server");

  char *answer=new char[plen];
  try {
    timeoutReadn(answer,plen);
    *replen=plen;
    return answer;
  }
  catch(...) {
    delete answer;
    throw; // whop!
  }
  return 0;
}

int Resolver::notify(int sock, const string &domain, const string &ip, u_int16_t id)
{
  DNSPacket p;
  p.setQuestion(Opcode::Notify,domain,QType::SOA);
  p.wrapup();
  p.spoofID(id);

  struct in_addr inp;
  Utility::inet_aton(ip.c_str(),&inp);

  struct sockaddr_in toaddr;
  toaddr.sin_addr.s_addr=inp.s_addr;

  toaddr.sin_port=htons(53);
  toaddr.sin_family=AF_INET;

  if(sendto(sock, p.getData(), p.len, 0, (struct sockaddr*)(&toaddr), sizeof(toaddr))<0) {
    throw ResolverException("Unable to send notify to "+ip+": "+stringerror());
  }
  return true;
}


int Resolver::resolve(const string &ip, const char *domain, int type)
{
  makeUDPSocket();
  DNSPacket p;

  p.setQuestion(Opcode::Query,domain,type);
  p.wrapup();

  d_domain=domain;
  d_type=type;
  d_inaxfr=false;

  struct sockaddr_in toaddr;
  struct in_addr inp;
  ServiceTuple st;
  st.port=53;
  parseService(ip, st);
  Utility::inet_aton(st.host.c_str(),&inp);
  toaddr.sin_addr.s_addr=inp.s_addr;

  toaddr.sin_port=htons(st.port);
  toaddr.sin_family=AF_INET;

  if(sendto(d_sock, p.getData(), p.len, 0, (struct sockaddr*)(&toaddr), sizeof(toaddr))<0) {
    throw ResolverException("Unable to ask query of "+st.host+":"+itoa(st.port)+": "+stringerror());
  }

  Utility::socklen_t addrlen=sizeof(toaddr);

  fd_set rd;
  FD_ZERO(&rd);
  FD_SET(d_sock, &rd);

  struct timeval timeout;
  timeout.tv_sec=1;
  timeout.tv_usec=500000;

  int res=select(d_sock+1,&rd,0,0,&timeout);

  if(!res)
    throw ResolverException("Timeout waiting for answer from "+ip);
  if(res<0)
    throw ResolverException("Error waiting for answer: "+stringerror());


  if((d_len=recvfrom(d_sock, reinterpret_cast< char * >( d_buf ), 512,0,(struct sockaddr*)(&toaddr), &addrlen))<0) 
    throw ResolverException("recvfrom error waiting for answer: "+stringerror());

  return 1;
}

void Resolver::makeTCPSocket(const string &ip, u_int16_t port)
{
  if(d_sock>=0)
    return;
  struct sockaddr_in toaddr;
  struct in_addr inp;
  Utility::inet_aton(ip.c_str(),&inp);
  toaddr.sin_addr.s_addr=inp.s_addr;

  toaddr.sin_port=htons(port);
  toaddr.sin_family=AF_INET;
  

  d_sock=socket(AF_INET,SOCK_STREAM,0);
  if(d_sock<0)
    throw ResolverException("Unable to make a TCP socket for resolver: "+stringerror());
  
  Utility::setNonBlocking( d_sock );

  int err;
#ifndef WIN32
  if((err=connect(d_sock,(struct sockaddr*)&toaddr,sizeof(toaddr)))<0 && errno!=EINPROGRESS) {
#else
  if((err=connect(d_sock,(struct sockaddr*)&toaddr,sizeof(toaddr)))<0 && WSAGetLastError() != WSAEWOULDBLOCK ) {
#endif // WIN32
    throw ResolverException("connect: "+stringerror());
  }

  if(!err)
    goto done;

  fd_set rset,wset;
  struct timeval tval;

  FD_ZERO(&rset);
  FD_SET(d_sock, &rset);
  wset=rset;
  tval.tv_sec=10;
  tval.tv_usec=0;

  if(!select(d_sock+1,&rset,&wset,0,tval.tv_sec ? &tval : 0)) {
    Utility::closesocket(d_sock); // timeout
    d_sock=-1;
    errno=ETIMEDOUT;
    
    throw ResolverException("Timeout connecting to server");
  }
  
  if(FD_ISSET(d_sock, &rset) || FD_ISSET(d_sock, &wset))
    {
    Utility::socklen_t len=sizeof(err);
      if(getsockopt(d_sock, SOL_SOCKET,SO_ERROR,(char *)&err,&len)<0)
	throw ResolverException("Error connecting: "+stringerror()); // Solaris

      if(err)
	throw ResolverException("Error connecting: "+string(strerror(err)));

    }
  else
    throw ResolverException("nonblocking connect failed");

 done:
  Utility::setBlocking( d_sock );
  // d_sock now connected
}


//! returns -1 for permanent error, 0 for timeout, 1 for success
int Resolver::axfr(const string &ip, const char *domain)
{
  d_domain=domain;

  makeTCPSocket(ip);

  d_type=QType::AXFR;
  DNSPacket p;
  p.setQuestion(Opcode::Query,domain,QType::AXFR);
  p.wrapup();

  int replen=htons(p.len);
  Utility::iovec iov[2];
  iov[0].iov_base=(char*)&replen;
  iov[0].iov_len=2;
  iov[1].iov_base=(char*)p.getData();
  iov[1].iov_len=p.len;

  int ret=Utility::writev(d_sock,iov,2);
  if(ret<0)
    throw ResolverException("Error sending question to "+ip+": "+stringerror());

  fd_set rd;
  FD_ZERO(&rd);
  FD_SET(d_sock, &rd);

  struct timeval timeout;
  timeout.tv_sec=10;
  timeout.tv_usec=0;

  int res=select(d_sock+1,&rd,0,0,&timeout);
  if(!res)
    throw ResolverException("Timeout waiting for answer from "+ip+" during AXFR");
  if(res<0)
    throw ResolverException("Error waiting for answer from "+ip+": "+stringerror());

  d_soacount=0;
  d_inaxfr=true;
  return 1;
}

int Resolver::getLength()
{
  int bytesLeft=2;
  unsigned char buf[2];
  
  while(bytesLeft) {
    int ret=waitForData(d_sock, 10);
    if(ret<0) {
      Utility::closesocket(d_sock);
      throw ResolverException("Waiting on data from remote TCP client: "+stringerror());
    }
  
    ret=recv(d_sock, reinterpret_cast< char * >( buf ) +2-bytesLeft, bytesLeft,0);
    if(ret<0)
      throw ResolverException("Trying to read data from remote TCP client: "+stringerror());
    if(!ret) 
      return -1;
    
    bytesLeft-=ret;
  }
  return buf[0]*256+buf[1];
}

int Resolver::axfrChunk(Resolver::res_t &res)
{
  if(d_soacount>1) {
    Utility::closesocket(d_sock);
    d_sock=-1;
    return 0;
  }

  // d_sock is connected and is about to spit out a packet
  int len=getLength();
  if(len<0)
    throw ResolverException("EOF trying to read axfr chunk from remote TCP client");
  
  timeoutReadn((char *)d_buf,len); 
  d_len=len;

  res=result();
  for(res_t::const_iterator i=res.begin();i!=res.end();++i)
    if(i->qtype.getCode()==QType::SOA) {
      d_soacount++;
    }

  if(d_soacount>1 && !res.empty()) // chop off the last SOA
    res.resize(res.size()-1);
    

  return 1;
}


Resolver::res_t Resolver::result()
{
  try {
    DNSPacket p;
    
    if(p.parse((char *)d_buf, d_len)<0)
      throw ResolverException("resolver: unable to parse packet of "+itoa(d_len)+" bytes");
    
    if(p.d.rcode)
      if(d_inaxfr)
	throw ResolverException("Remote nameserver unable/unwilling to AXFR with us: RCODE="+itoa(p.d.rcode));
      else
	throw ResolverException("Remote nameserver reported error: RCODE="+itoa(p.d.rcode));
    
    if(!d_inaxfr) {
      if(ntohs(p.d.qdcount)!=1)
	throw ResolverException("resolver: received answer with wrong number of questions ("+itoa(ntohs(p.d.qdcount))+")");
      
      if(p.qdomain!=d_domain)
	throw ResolverException(string("resolver: received an answer to another question (")+p.qdomain+"!="+d_domain+")");
    }
    return p.getAnswers();
  }
  catch(AhuException &ae) { // translate
    throw ResolverException(ae.reason);
  }
}


int Resolver::getSoaSerial(const string &ip, const string &domain, u_int32_t *serial)
{
  resolve(ip,domain.c_str(),QType::SOA);
  res_t res=result();
  if(res.empty())
    return 0;
  
  vector<string>parts;
  stringtok(parts,res[0].content);
  if(parts.size()<3)
    return 0;
  
  *serial=atoi(parts[2].c_str());
  return 1;
}

