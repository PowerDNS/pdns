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
int d_clientsock;
int d_serversock;

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
  return sendto(d_clientsock, data, len, flags, toaddr, addrlen);
}

int arecvfrom(char *data, int len, int flags, struct sockaddr *toaddr, socklen_t *addrlen, int *d_len, int id)
{
  // don't do this, work via multiplexer
  PacketID pident;
  pident.id=id;
  memcpy(&pident.remote,toaddr,sizeof(pident.remote));
  
  string packet;
  if(!MT.waitEvent(pident,&packet,1)) { // timeout
    return 0; 
  }

  *d_len=packet.size();
  memcpy(data,packet.c_str(),min(len,*d_len));

  return 1;
}


extern void init(void);

int beginResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret);

void startDoResolve(void *p)
{
  try {
    DNSPacket P=*(DNSPacket *)p;
    delete (DNSPacket *)p;
    
    vector<DNSResourceRecord>ret;
    DNSPacket *R=P.replyPacket();
    R->setA(false);
    R->setRA(true);
    int res=beginResolve(P.qdomain, P.qtype, ret);
    if(res<0)
      R->setRcode(RCode::ServFail);
    else {
      R->setRcode(res);
      for(vector<DNSResourceRecord>::const_iterator i=ret.begin();i!=ret.end();++i)
	R->addRecord(*i);
    }

    const char *buffer=R->getData();
    sendto(d_serversock,buffer,R->len,0,(struct sockaddr *)(R->remote),R->d_socklen);
    delete R;
  }
  catch(AhuException &ae) {
    cerr<<"startDoResolve timeout: "<<ae.reason<<endl;
  }
  catch(...) {
    cerr<<"Any other exception"<<endl;
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
  sin.sin_addr.s_addr = INADDR_ANY;
  
  int tries=10;
  while(--tries) {
    u_int16_t port=10000+random()%10000;
    sin.sin_port = htons(port); 
    
    if (bind(d_clientsock, (struct sockaddr *)&sin, sizeof(sin)) >= 0) {
      cout<<"Outging query source port: "<<port<<endl;
      break;
    }
    
  }
  if(!tries)
    throw AhuException("Resolver binding to local socket: "+stringerror());
}

void makeServerSocket()
{
  d_serversock=socket(AF_INET, SOCK_DGRAM,0);
  if(d_serversock<0) 
    throw AhuException("Making a server socket for resolver: "+stringerror());
  
  struct sockaddr_in sin;
  memset((char *)&sin,0, sizeof(sin));
  
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(arg().asNum("local-port")); 
    
  if (bind(d_serversock, (struct sockaddr *)&sin, sizeof(sin))<0) 
    throw AhuException("Resolver binding to server socket: "+stringerror());
  cout<<"Incoming query source port: "<<arg().asNum("local-port")<<endl;
}


int main(int argc, char **argv) 
{
#if __GNUC__ >= 3
    ios_base::sync_with_stdio(false);
#endif

  try {
    srandom(time(0));
    arg().set("soa-minimum-ttl","0")="0";
    arg().set("soa-serial-offset","0")="0";
    arg().set("local-port","port to listen on")="5300";
    arg().parse(argc, argv);
    init();
    cerr<<"Done priming cache with root hints"<<endl;

    makeClientSocket();
    makeServerSocket();
    
    char data[1500];
    struct sockaddr_in fromaddr;
    
    PacketID pident;
    
    for(;;) {
      while(MT.schedule()); // housekeeping, let threads do their thing
      
      socklen_t addrlen=sizeof(fromaddr);
      int d_len;
      DNSPacket P;
      
      struct timeval tv;
      tv.tv_sec=0;
      tv.tv_usec=500000;
      
      fd_set readfds;
      FD_ZERO( &readfds );
      FD_SET( d_clientsock, &readfds );
      FD_SET( d_serversock, &readfds );
      int selret = select( max(d_clientsock,d_serversock) + 1, &readfds, NULL, NULL, &tv );
      if (selret == -1) 
	  throw AhuException("Select returned: "+stringerror());
      if(!selret) // nothing happened
	continue;
      
      if(FD_ISSET(d_clientsock,&readfds)) { // do we have a question response?
	d_len=recvfrom(d_clientsock, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);    
	if(d_len<0) {
	  cerr<<"Recvfrom returned error, retrying: "<<strerror(errno)<<endl;
	  continue;
	}
	
	P.setRemote((struct sockaddr *)&fromaddr, addrlen);
	if(P.parse(data,d_len)<0) {
	  cerr<<"Unparseable packet from "<<P.getRemote()<<endl;
	}
	else { 
	  if(P.d.qr) {
	    //	    cout<<"answer to a question received"<<endl;
	    //      cout<<"Packet from "<<P.getRemote()<<" with id "<<P.d.id<<": "; cout.flush();
	    pident.remote=fromaddr;
	    pident.id=P.d.id;
	    string *packet=new string;
	    packet->assign(data,d_len);
	    MT.sendEvent(pident,packet);
	  }
	  else 
	    cout<<"Ignoring question on outgoing socket!"<<endl;
	}
      }
      
      if(FD_ISSET(d_serversock,&readfds)) { // do we have a new question?
	d_len=recvfrom(d_serversock, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);    
	if(d_len<0) {
	  cerr<<"Recvfrom returned error, retrying: "<<strerror(errno)<<endl;
	  continue;
	}
	
	P.setRemote((struct sockaddr *)&fromaddr, addrlen);
	if(P.parse(data,d_len)<0) {
	  cerr<<"Unparseable packet from "<<P.getRemote()<<endl;
	}
	else { 
	  if(P.d.qr)
	    cout<<"Ignoring answer on server socket!"<<endl;
	  else {
	    cout<<"new question arrived for '"<<P.qdomain<<"|"<<P.qtype.getName()<<"'"<<endl;
	    MT.makeThread(startDoResolve,(void*)new DNSPacket(P));
	  }
	}
      }
    }
  }
  catch(AhuException &ae) {
    cerr<<"Exception: "<<ae.reason<<endl;
  }
  catch(exception &e) {
    cerr<<"STL Exception: "<<e.what()<<endl;
  }
  catch(...) {
    cerr<<"any other exception in main: "<<endl;
  }
}
