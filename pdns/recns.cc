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
#include <set>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mtasker.hh"
#include <utility>
#include "dnspacket.hh"
#include "statbag.hh"
#include "arguments.hh"
#include "syncres.hh"

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

MTasker<PacketID,string> MT(100000);

/* these two functions are used by LWRes */
int asendto(const char *data, int len, int flags, struct sockaddr *toaddr, int addrlen, int id) 
{
  return sendto(d_clientsock, data, len, flags, toaddr, addrlen);
}

int arecvfrom(char *data, int len, int flags, struct sockaddr *toaddr, socklen_t *addrlen, int *d_len, int id)
{
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


typedef map<string,set<DNSResourceRecord> > cache_t;
cache_t cache;
int getCache(const string &qname, const QType& qt, set<DNSResourceRecord>* res)
{
  string line;
  static FILE* fp;

  line="Q: "+qname+". "+itoa(qt.getCode())+"\n";

  write(d_serversock,line.c_str(),line.size());
  if(!fp) {
    fp=fdopen(d_serversock,"r");
    setbuf(fp,0); // no buffering please, confuses select
  }

  char rline[1024];
  u_int32_t lastttl=0;
  while(fgets(rline,sizeof(rline)-1,fp)) {
    line=rline;
    stripLine(line);
    cout<<"Got a line from pdns! '"<<line<<"'"<<endl;
    if(line.empty()) {
      cout<<"Cache answer done"<<endl;
      break;
    }
    DNSResourceRecord rr;
    rr.unSerialize(line);
    if(res)
      res->insert(rr);
    lastttl=rr.ttl;
  }
  if(lastttl)
    return (unsigned int)lastttl-time(0);


  /*
  cache_t::const_iterator j=cache.find(toLower(qname)+"|"+qt.getName());
  if(j!=cache.end() && j->first==toLower(qname)+"|"+qt.getName() && j->second.begin()->ttl>(unsigned int)time(0)) {
    if(res)
      *res=j->second;
    return (unsigned int)j->second.begin()->ttl-time(0);
  }
  */
  return -1;
}

void replaceCache(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content)
{
  string line;
  line="A: "+qname+". "+itoa(qt.getCode())+" ";
  unsigned int minttl=1<<30;

  for(set<DNSResourceRecord>::const_iterator i=content.begin();i!=content.end();++i)
    minttl=min(minttl-time(0),i->ttl-time(0));
  line+=itoa(minttl)+"\n";

  for(set<DNSResourceRecord>::const_iterator i=content.begin();i!=content.end();++i)
    line+=i->serialize()+"\n";
  line+="\n";
  write(d_serversock,line.c_str(),line.size());
  /*
  cache[tuple]=content;
  */
}

void init(void)
{
  // prime root cache
  static char*ips[]={"198.41.0.4", "128.9.0.107", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
		     "192.36.148.17","198.41.0.10", "193.0.14.129", "198.32.64.12", "202.12.27.33"};
  DNSResourceRecord arr, nsrr;
  arr.qtype=QType::A;
  arr.ttl=time(0)+86400;
  nsrr.qtype=QType::NS;
  nsrr.ttl=time(0)+86400;
  
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
    DNSPacket P=*(DNSPacket *)p;
    delete (DNSPacket *)p;
    
    vector<DNSResourceRecord>ret;
    DNSPacket *R=P.replyPacket();
    R->setA(false);
    R->setRA(true);

    SyncRes<LWRes> sr;

    int res=sr.beginResolve(P.qdomain, P.qtype, ret);
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
    cerr<<"startDoResolve problem: "<<ae.reason<<endl;
  }
  catch(...) {
    cerr<<"Any other exception"<<endl;
  }
}

void startDoResolveEmbed(void *p)
{
  try {
    DNSPacket P=*(DNSPacket *)p;
    delete (DNSPacket *)p;
    
    vector<DNSResourceRecord>ret;
    SyncRes<LWRes> sr;
    int res=sr.beginResolve(P.qdomain, P.qtype, ret);
    P.setRA(true);
    P.commitD();
    string line="P: "+P.qdomain+" "+itoa(P.qtype.getCode())+" "+itoa(P.getSocket())+" "+itoa(P.d.id)+" ";
    line+=itoa(*(((char*)&P.d)+2))+" "+P.getRemote()+" "+itoa(P.getRemotePort())+" ";
    if(res<0)
      line+=itoa(RCode::ServFail)+"\n\n";
    else {
      line+=itoa(res)+"\n";

      for(vector<DNSResourceRecord>::const_iterator i=ret.begin();i!=ret.end();++i) {
	line.append(1,(char)(i->d_place+'0'));
	line+=i->serialize()+"\n";
      }
      line+="\n";
    }
    write(d_serversock,line.c_str(),line.size());
  }
  catch(AhuException &ae) {
    cerr<<"startDoResolve problem: "<<ae.reason<<endl;
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

  if(arg()["local-address"]=="0.0.0.0") {
    cerr<<"It is advised to bind to explicit addresses with the --local-address option"<<endl;
    sin.sin_addr.s_addr = INADDR_ANY;
  }
  else {
    struct hostent *h=0;
    h=gethostbyname(arg()["local-address"].c_str());
    if(!h)
      throw AhuException("Unable to resolve local address"); 
    
    sin.sin_addr.s_addr=*(int*)h->h_addr;
  }

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
    cout<<"argc="<<argc<<endl;
    srandom(time(0));
    arg().set("soa-minimum-ttl","0")="0";
    arg().set("soa-serial-offset","0")="0";
    arg().set("local-port","port to listen on")="5300";
    arg().set("local-address","port to listen on")="0.0.0.0";
    arg().parse(argc, argv);

    cerr<<"Done priming cache with root hints"<<endl;

    
    makeClientSocket();
    if(argc==1)
      makeServerSocket();
    else {
      cout<<"Launched within pdns! Socket="<<atoi(argv[1])<<endl;
      d_serversock=atoi(argv[1]);
    }
    
    char data[1500];
    struct sockaddr_in fromaddr;
    
    PacketID pident;
    init();    
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
	cout<<"question on the serversock"<<endl;
	if(argc==1) {
	  d_len=recvfrom(d_serversock, data, sizeof(data), 0, (sockaddr *)&fromaddr, &addrlen);    
	  if(d_len<0) {
	    cerr<<"Recvfrom returned error, retrying: "<<strerror(errno)<<endl;
	    continue;
	  }
	  cout<<"Read "<<d_len<<" bytes?!"<<endl;
	  P.setRemote((struct sockaddr *)&fromaddr, addrlen);
	  if(P.parse(data,d_len)<0) {
	    cerr<<"Unparseable packet from "<<P.getRemote()<<endl;
	  }
	  else { 
	    if(P.d.qr)
	      cout<<"Ignoring answer on server socket!"<<endl;
	    else {
	      cout<<"new question arrived for '"<<P.qdomain<<"|"<<P.qtype.getName()<<"' from "<<P.getRemote()<<endl;
	      MT.makeThread(startDoResolve,(void*)new DNSPacket(P));
	    }
	  }
	}
	else {
	  string line;
	  cout<<"About to read"<<endl;
	  int len=read(d_serversock,data,sizeof(data));
	  cout<<"done reading, len="<<len<<endl;
	  if(len<=0) {
	    cout<<"shit on the pdns socket"<<endl;
	    exit(1);
	  }
	  line.assign(data,len);
	  stripLine(line);
	  cout<<"pdns gave us a question: '"<<line<<"'"<<endl;
	  vector<string>parts;
	  stringtok(parts,line," ");
	  P.setQuestion(0,parts[0],atoi(parts[1].c_str()));
	  P.setSocket(atoi(parts[2].c_str()));
	  P.d.id=atoi(parts[3].c_str());
	  *((char *)&P.d+2)=atoi(parts[4].c_str()); // spoof in flags
	  struct sockaddr_in fromaddr;
	  socklen_t addrlen=sizeof(fromaddr);

	  struct in_addr inp;
	  Utility::inet_aton(parts[5].c_str(),&inp);
	  fromaddr.sin_addr.s_addr=inp.s_addr;
	  
	  fromaddr.sin_port=htons(atoi(parts[6].c_str())); // hmf
	  fromaddr.sin_family=AF_INET;

	  P.setRemote((struct sockaddr *)&fromaddr, addrlen);
	  MT.makeThread(startDoResolveEmbed,(void*)new DNSPacket(P));
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
