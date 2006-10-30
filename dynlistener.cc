 /*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2006  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <cstring>
#include <string>
#include <map>
#include <sys/types.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "misc.hh"
#include "dns.hh"
#include "arguments.hh"
#include "dnsbackend.hh"
#include "dynlistener.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "statbag.hh"



extern StatBag S;

DynListener::~DynListener()
{
  if(!d_socketname.empty())
    unlink(d_socketname.c_str());
}

DynListener::DynListener(const string &pname)
{
  d_restfunc=0;
  string programname(pname);

  if(!programname.empty()) {
    struct sockaddr_un local;
    d_s=socket(AF_UNIX,SOCK_STREAM,0);

    if(d_s<0) {
      L<<Logger::Error<<"Creating socket for dynlistener: "<<strerror(errno)<<endl;;
      exit(1);
    }

    int tmp=1;
    if(setsockopt(d_s,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
      throw AhuException(string("Setsockopt failed: ")+strerror(errno));
    
    string socketname=arg()["socket-dir"]+"/";
    cleanSlashes(socketname);
    
    if(!mkdir(socketname.c_str(),0700)) // make /var directory, if needed
      L<<Logger::Warning<<"Created local state directory '"<<socketname<<"'"<<endl;
    else if(errno!=EEXIST) {
      L<<Logger::Critical<<"FATAL: Unable to create socket directory ("<<socketname<<") and it does not exist yet"<<endl;
      exit(1);
    }
    
    socketname+=programname+".controlsocket";
    int err=unlink(socketname.c_str());
    if(err < 0 && errno!=ENOENT) {
      L<<Logger::Critical<<"Unable to remove (previous) controlsocket: "<<strerror(errno)<<endl;
      exit(1);
    }
    memset(&local,0,sizeof(local));
    local.sun_family=AF_UNIX;
    strcpy(local.sun_path,socketname.c_str());
    
    if(bind(d_s, (sockaddr*)&local,sizeof(local))<0) {
      L<<Logger::Critical<<"Binding to dynlistener '"<<socketname<<"': "<<strerror(errno)<<endl;
      exit(1);
    }
    d_socketname=socketname;
    if(!arg()["setgid"].empty()) {
      if(chown(socketname.c_str(),static_cast<uid_t>(-1),Utility::makeGidNumeric(arg()["setgid"]))<0)
	L<<Logger::Error<<"Unable to change group ownership of controlsocket: "<<strerror(errno)<<endl;
      if(chmod(socketname.c_str(),0660)<0)
	L<<Logger::Error<<"Unable to change group access mode of controlsocket: "<<strerror(errno)<<endl;
    }
      

    L<<Logger::Warning<<"Listening on controlsocket in '"<<socketname<<"'"<<endl;
    d_udp=true;
    listen(d_s,10);
  }
  else
    d_udp=false;


}

void DynListener::go()
{
  d_ppid=getpid();
  pthread_create(&d_tid,0,&DynListener::theListenerHelper,this);
}

void *DynListener::theListenerHelper(void *p)
{
  DynListener *us=static_cast<DynListener *>(p);
  us->theListener();
  return 0;
}

string DynListener::getLine()
{
  char mesg[512];
  memset(mesg,0,sizeof(mesg));
  int len;
    
  sockaddr_un remote;
  socklen_t remlen=sizeof(remote);

  if(d_udp) {
    for(;;) {
      d_client=accept(d_s,(sockaddr*)&remote,&remlen);
      if(d_client<0) {
	if(errno!=EINTR)
	  L<<Logger::Error<<"Unable to accept controlsocket connection ("<<d_s<<"): "<<strerror(errno)<<endl;
	continue;
      }
      if((len=recv(d_client,mesg,512,0))<0) {
	L<<Logger::Error<<"Unable to receive packet from controlsocket ("<<d_client<<"): "<<strerror(errno)<<endl;
	close(d_client);
	continue;
      }
      break;
    }
  }
  else {
    if(isatty(0))
      write(1, "% ", 2);
    if((len=read(0,mesg,512))<0) 
      throw AhuException("Reading from the control pipe: "+stringerror());
    else if(len==0)
      throw AhuException("Guardian exited - going down as well");
  }
  
  return mesg;
}

void DynListener::sendLine(const string &l)
{
  if(d_udp) {
    unsigned int sent=0;
    int ret;
    while(sent<l.length()) {
      ret=send(d_client,l.c_str()+sent,l.length()-sent,0); 
      if(ret<0 || !ret) {
	L<<Logger::Error<<"Error sending data to pdns_control: "<<stringerror()<<endl;
	break;
      }
      sent+=ret;
    }
    close(d_client);
  }
  else {
    string line=l;
    if(!line.empty() && line[line.length()-1]!='\n')
      line.append("\n");
    line.append("\n");
    write(1,line.c_str(),line.length());
  }
}

void DynListener::registerFunc(const string &name, g_funk_t *gf)
{
  d_funcdb[name]=gf;
}

void DynListener::registerRestFunc(g_funk_t *gf)
{
  d_restfunc=gf;
}

void DynListener::theListener()
{
  try {
    map<string,string> parameters;

    for(;;) {
      string line=getLine();
      chomp(line,"\n");

      vector<string>parts;
      stringtok(parts,line," ");
      if(parts.empty()) {
	sendLine("Empty line");
	continue;
      }
      parts[0] = toUpper( parts[0] );
      if(!d_funcdb[parts[0]]) {
	if(d_restfunc) 
	  sendLine((*d_restfunc)(parts,d_ppid));
	else
	  sendLine("Unknown command: '"+parts[0]+"'");
	continue;
      }

      sendLine((*d_funcdb[parts[0]])(parts,d_ppid));
    }
  }
  catch(AhuException &AE)
    {
      L<<Logger::Error<<"Fatal error in control listener: "<<AE.reason<<endl;
    }
  catch(string &E)
    {
      L<<Logger::Error<<"Fatal error 2 in control listener: "<<E<<endl;
    }
  catch(exception& e)
    {
      L<<Logger::Error<<"Fatal STL error: "<<e.what()<<endl;
    }
  catch(...)
    {
      L<<Logger::Error<<"Fatal: unknown exception occured"<<endl;
    }
}

