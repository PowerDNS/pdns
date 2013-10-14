/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2012 PowerDNS.COM BV

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
#include "session.hh"
#include "pdnsexception.hh"
#include "misc.hh"
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <fcntl.h>
#include <sstream>
#include "misc.hh"
#include "iputils.hh"

void Session::init()
{
  d_bufsize=15049; // why?!

  d_verbose=false;

  rdbuf=new char[d_bufsize];  
  rdoffset=0;
  wroffset=0;
}

void Session::beVerbose()
{
  d_verbose=true;
}

Session::Session(int s, struct sockaddr_in r)
{
  init();
  remote=r;
  clisock=s;
}

int Session::close()
{
  int rc=0;
  
  if(clisock>=0)
    rc=Utility::closesocket(clisock);

  clisock=-1;
  return rc;
}

Session::~Session()
{

  /* NOT CLOSING AUTOMATICALLY ANYMORE!
    if(clisock>=0)
    ::close(clisock);
  */  

  delete[] rdbuf;
}

//! This function makes a deep copy of Session
Session::Session(const Session &s)
{
  d_bufsize=s.d_bufsize;

  init(); // needs d_bufsize, but will reset rdoffset & wroffset

  rdoffset=s.rdoffset;
  wroffset=s.wroffset;
  clisock=s.clisock;
  remote=s.remote;

  memcpy(rdbuf,s.rdbuf,d_bufsize);
}  

void Session::setTimeout(unsigned int seconds)
{
  d_timeout=seconds;
}

  
bool Session::putLine(const string &s)
{
  int length=s.length();
  int written=0;
  int err;

  while(written < length)
    {
      err=waitForRWData(clisock, false, d_timeout, 0);
      if(err<=0)
        throw SessionException("nonblocking write failed: "+string(strerror(errno)));

      err = send(clisock, s.c_str() + written, length-written, 0);

      if(err < 0)
        return false;
      
      written+=err;
    }

  return true;
}

char *strnchr(char *p, char c, int len)
{
  int n;
  for(n=0;n<len;n++)
    if(p[n]==c)
      return p+n;
  return 0;
}

string Session::get(unsigned int bytes)
{
  string ret;
  if(wroffset - rdoffset >= (int)bytes) 
  {
    ret = string(rdbuf + rdoffset, bytes);
    bytes -= ret.length();
    rdoffset += ret.length();
  }
  
  if(bytes) {
    scoped_array<char> buffer(new char[bytes]);
    int err = read(clisock, &buffer[0], bytes);  // XXX FIXME should be nonblocking
    if(err < 0)
      throw SessionException("Error reading bytes from client: "+string(strerror(errno)));
    if(err != (int)bytes)
      throw SessionException("Error reading bytes from client: partial read");
    ret.append(&buffer[0], err);
  }
  return ret;
}

int Session::timeoutRead(int s, char *buf, size_t len)
{
  int err = waitForRWData(s, true, d_timeout, 0);
  
  if(!err)
    throw SessionTimeoutException("timeout reading");
  if(err < 0)
    throw SessionException("nonblocking read failed: "+string(strerror(errno)));
  
  return recv(s,buf,len,0);
}

bool 
Session::haveLine()
{
  return (wroffset!=rdoffset && (strnchr(rdbuf+rdoffset,'\n',wroffset-rdoffset)!=NULL));
}
        

bool 
Session::getLine(string &line)
{
  int bytes;
  char *p;

  int linelength;
  
  // read data into a buffer
  // find first \n, and return that as string, store how far we were

  for(;;)
    {
      if(wroffset==rdoffset)
        {
          wroffset=rdoffset=0;
        }

      if(wroffset!=rdoffset && (p=strnchr(rdbuf+rdoffset,'\n',wroffset-rdoffset))) // we have a full line in store, return that 
        {
          // from rdbuf+rdoffset to p should become the new line

          linelength=p-(rdbuf+rdoffset); 
          
          *p=0; // terminate
          
          line=rdbuf+rdoffset;
          line+="\n";
          
          rdoffset+=linelength+1;

          return true;
        }
      // we need more data before we can return a line

      if(wroffset==d_bufsize) // buffer is full, flush to left
        {
          if(!rdoffset) // line too long!
            {
              // FIXME: do stuff
              close();
              return false;
            }

          memmove(rdbuf,rdbuf+rdoffset,wroffset-rdoffset);
          wroffset-=rdoffset;
          rdoffset=0;
        }
      bytes=timeoutRead(clisock,rdbuf+wroffset,d_bufsize-wroffset);

      if(bytes<0)
          throw SessionException("error on read from socket: "+string(strerror(errno)));

      if(bytes==0)
        throw SessionException("Remote closed connection");

      wroffset+=bytes;
    }
  // we never get here
}
  
int Session::getSocket()
{
  return clisock;
}

string Session::getRemote ()
{
  ostringstream o;
  uint32_t rint=htonl(remote.sin_addr.s_addr);
  o<< (rint>>24 & 0xff)<<".";
  o<< (rint>>16 & 0xff)<<".";
  o<< (rint>>8  & 0xff)<<".";
  o<< (rint     & 0xff);
  o<<":"<<htons(remote.sin_port);

  return o.str();
}

uint32_t Session::getRemoteAddr()
{

  return htonl(remote.sin_addr.s_addr);
}

string Session::getRemoteIP()
{
  ostringstream o;
  uint32_t rint=htonl(remote.sin_addr.s_addr);
  o<< (rint>>24 & 0xff)<<".";
  o<< (rint>>16 & 0xff)<<".";
  o<< (rint>>8  & 0xff)<<".";
  o<< (rint     & 0xff);

  return o.str();
}
  

Session *Server::accept()
{
  struct sockaddr_in remote;
  Utility::socklen_t len=sizeof(remote);

  int clisock=-1;


  while((clisock=::accept(s,(struct sockaddr *)(&remote),&len))==-1) // repeat until we have a successful connect
    {
      //      L<<Logger::Error<<"accept() returned: "<<strerror(errno)<<endl;
      if(errno==EMFILE) {
        throw SessionException("Out of file descriptors - won't recover from that");
      }

    }

  return new Session(clisock, remote);
}

Server::Server(int port, const string &localaddress)
{
  d_local = ComboAddress(localaddress.empty() ? "0.0.0.0" : localaddress, port);
  s = socket(d_local.sin4.sin_family ,SOCK_STREAM,0);

  if(s < 0)
    throw SessionException(string("socket: ")+strerror(errno));

  Utility::setCloseOnExec(s);
  
  int tmp=1;
  if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
    throw SessionException(string("Setsockopt failed: ")+strerror(errno));

  if(bind(s, (sockaddr*)&d_local, d_local.getSocklen())<0)
    throw SessionException("binding to "+d_local.toStringWithPort()+": "+strerror(errno));
  
  if(listen(s,128)<0)
    throw SessionException("listen: "+stringerror());
}

