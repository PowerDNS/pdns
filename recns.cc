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
 

#include <iostream>
#include <errno.h>
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mtasker.hh"
#include <utility>
#include "dnspacket.hh"
#include "statbag.hh"
#include "arguments.hh"


extern "C" {
  int sem_init(sem_t*, int, unsigned int){return 0;}
  int sem_wait(sem_t*){return 0;}
  int sem_trywait(sem_t*){return 0;}
  int sem_post(sem_t*){return 0;}
  int sem_getvalue(sem_t*, int*){return 0;}
}

StatBag S;
ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}
int d_sock;

struct PacketID
{
  u_int16_t id;
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

MTasker<PacketID,string> MT(200000);

int asendto(const char *data, int len, int flags, struct sockaddr *toaddr, int addrlen, int id) 
{

  return sendto(d_sock, data, len, flags, toaddr, addrlen);
}

int arecvfrom(char *data, int len, int flags, struct sockaddr *toaddr, socklen_t *addrlen, int *d_len, int id)
{
  // don't do this, work via multiplexer
  PacketID pident;
  pident.id=id;
  memcpy(&pident.remote,toaddr,sizeof(pident.remote));
  
  string packet;
  if(!MT.waitEvent(pident,&packet,5)) {
    cerr<<"TIMEOUT!!!"<<endl;
    throw AhuException("Timeout!");
  }

  *d_len=packet.size();
  memcpy(data,packet.c_str(),min(len,*d_len));

  return 1;
}


extern void init(void);
string doResolve(const string &qname, int depth=0);
string doResolve(vector<string> nameservers, const string &qname, int depth=0);


void startDoResolve(void *p)
{
  try {
    cout<<"Passed: "<<p<<endl;
    DNSPacket P=*(DNSPacket *)p;
    delete (DNSPacket *)p;
    
    string ip=doResolve(P.qdomain);
    cout<<"done: "<<ip<<endl;
    DNSPacket *R=P.replyPacket();
    DNSResourceRecord rr;
    rr.qname=P.qdomain;
    rr.qtype=QType::A;
    rr.content=ip;
    rr.ttl=3600;
    R->addRecord(rr);
    const char *buffer=R->getData();
    sendto(d_sock,buffer,R->len,0,(struct sockaddr *)(R->remote),R->d_socklen);
  }
  catch(AhuException &ae) {
    cerr<<"startDoResolve timeout: "<<ae.reason<<endl;
  }
  catch(...) {
    cerr<<"Any other exception"<<endl;
  }
}

int main(int argc, char **argv) 
{
#if __GNUC__ >= 3
    ios_base::sync_with_stdio(false);
#endif

  try {
    init();
    cerr<<"Done priming"<<endl;

    static u_int16_t port_counter=5000;
    
    d_sock=socket(AF_INET, SOCK_DGRAM,0);
    if(d_sock<0) 
      throw AhuException("Making a socket for resolver: "+stringerror());
    
    struct sockaddr_in sin;
    memset((char *)&sin,0, sizeof(sin));
    
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    
    int tries=10;
    while(--tries) {
      sin.sin_port = htons(10000+(port_counter++)%10000); // should be random!
      
      if (bind(d_sock, (struct sockaddr *)&sin, sizeof(sin)) >= 0) {
	cout<<"Bound to port "<<10000+port_counter-1<<endl;
	break;
      }
      
    }
    if(!tries)
      throw AhuException("Resolver binding to local socket: "+stringerror());
    
    char data[1500];
    struct sockaddr_in fromaddr;
    
    PacketID pident;
    
    for(;;) {
      while(MT.schedule()); // housekeeping, let threads do their thang
      
      socklen_t addrlen=sizeof(fromaddr);
      int d_len;
      DNSPacket P;
      
      for(;;) {
	d_len=recvfrom(d_sock, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);    
	if(d_len<0) {
	  cerr<<"Recvfrom returned error, retrying: "<<strerror(errno)<<endl;
	  continue;
	}
	
	P.setRemote((struct sockaddr *)&fromaddr, addrlen);
	if(P.parse(data,d_len)<0) {
	  cerr<<"Unparseable packet from "<<P.getRemote()<<endl;
	  continue;
	}
	break;
      }
      cout<<"Packet from "<<P.getRemote()<<" with id "<<P.d.id<<": "; cout.flush();
      if(P.d.qr) {
	cout<<"answer to a question"<<endl;
	pident.remote=fromaddr;
	pident.id=P.d.id;
	string *packet=new string;
	packet->assign(data,d_len);
	MT.sendEvent(pident,packet);
      }
      else {
	cout<<"new question for '"<<P.qdomain<<"'"<<endl;
	MT.makeThread(startDoResolve,(void*)new DNSPacket(P));
      }
    }
  }
  catch(AhuException &ae) {
    cerr<<"Exception: "<<ae.reason<<endl;
  }
  catch(...) {
    cerr<<"any other exception in main"<<endl;
  }
}
