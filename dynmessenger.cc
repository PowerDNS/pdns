/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2008  PowerDNS.COM BV

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
#include "dynmessenger.hh"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>

DynMessenger::DynMessenger(const string &localdir, const string &fname)
{
  d_s=socket(AF_UNIX,SOCK_STREAM,0);
  
  if(d_s<0) {
    throw AhuException(string("socket")+strerror(errno));
  }
  
  memset(&d_local,0,sizeof(d_local));

  string localname=localdir;

  localname+="/lsockXXXXXX";
  d_local.sun_family=AF_UNIX;
  strcpy(d_local.sun_path,localname.c_str());

  if(mkstemp(d_local.sun_path)<0)
    throw AhuException("Unable to generate local temporary file: "+string(strerror(errno)));
  
  unlink(d_local.sun_path);
  
  if(bind(d_s, (sockaddr*)&d_local,sizeof(d_local))<0) {
    unlink(d_local.sun_path);
    throw AhuException("Unable to bind to local temporary file: "+string(strerror(errno)));
  }
  
  if(chmod(d_local.sun_path,0666)<0) { // make sure that pdns can reply!
    unlink(d_local.sun_path);
    perror("fchmod");
    exit(1);
  }

  memset(&d_remote,0,sizeof(d_remote));
  
  d_remote.sun_family=AF_UNIX;
  strcpy(d_remote.sun_path,fname.c_str());
  if(connect(d_s,(sockaddr*)&d_remote,sizeof(d_remote))<0) {
    unlink(d_local.sun_path);
    throw AhuException("Unable to connect to remote '"+fname+"': "+string(strerror(errno)));
  }
  
}

DynMessenger::DynMessenger(const ComboAddress& remote, const string &secret)
{
  *d_local.sun_path=0;
  d_s=socket(AF_INET, SOCK_STREAM,0);
  
  if(d_s<0) {
    throw AhuException(string("socket")+strerror(errno));
  }
  
  if(connect(d_s, (sockaddr*)&remote, remote.getSocklen())<0) {
    close(d_s);
    throw AhuException("Unable to connect to remote '"+remote.toStringWithPort()+"': "+string(strerror(errno)));
  }

  string login=secret+"\n";
  writen2(d_s, login);
}

DynMessenger::~DynMessenger()
{
  if(*d_local.sun_path && unlink(d_local.sun_path)<0)
    cerr<<"Warning: unable to unlink local unix domain endpoint: "<<strerror(errno)<<endl;
  close(d_s);
}   

int DynMessenger::send(const string &msg) const
{
  if(writen2(d_s, msg+"\n") < 0) { // sue me
    perror("sendto");
    return -1;
  }
  return 0;
}

string DynMessenger::receive() const 
{
  char buffer[1500];

  int retlen;
  string answer;
  for(;;) {
    retlen=recv(d_s,buffer,sizeof(buffer),0);
    if(retlen<0)
      throw AhuException("Error from remote: "+string(strerror(errno)));

    answer.append(buffer,retlen);
    if(retlen!=sizeof(buffer))
      break;
  }

  return answer;
}

