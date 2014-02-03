/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2012 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

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

Session::Session(int s, ComboAddress r) : d_good(true)
{
  d_remote=r;
  d_socket=s;
}

Session::Session() : d_good(false)
{
}

int Session::close()
{
  int rc=0;
  
  if(d_socket>=0)
    rc=Utility::closesocket(d_socket);

  d_socket=-1;
  return rc;
}

Session::~Session()
{
  /* NOT CLOSING AUTOMATICALLY ANYMORE!
    if(d_socket>=0)
    ::close(d_socket);
  */  
}

//! This function makes a deep copy of Session
Session::Session(const Session &s)
{
  d_socket=s.d_socket;
  d_remote=s.d_remote;
  d_good=s.d_good;
  d_timeout=s.d_timeout;
}

void Session::setTimeout(unsigned int seconds)
{
  d_timeout=seconds;
}

bool Session::put(const string &s)
{
  int length=s.length();
  int written=0;
  int err;

  while(written < length)
    {
      err=waitForRWData(d_socket, false, d_timeout, 0);
      if(err<=0)
        throw SessionException("nonblocking write failed: "+string(strerror(errno)));

      err = send(d_socket, s.c_str() + written, length-written, 0);

      if(err < 0)
        return false;
      
      written+=err;
    }

  return true;
}

static int timeoutRead(int s, char *buf, size_t len, int timeout)
{
  int err = waitForRWData(s, true, timeout, 0);
  
  if(!err)
    throw SessionTimeoutException("timeout reading");
  if(err < 0)
    throw SessionException("nonblocking read failed: "+string(strerror(errno)));
  
  return recv(s,buf,len,0);
}

bool Session::good()
{
  return d_good;
}

size_t Session::read(char* buf, size_t len)
{
  int bytes;
  bytes = timeoutRead(d_socket, buf, len, d_timeout);

  if(bytes<0)
    throw SessionException("error on read from socket: "+string(strerror(errno)));

  if(bytes==0)
    d_good = false;

  return bytes;
}

int Session::getSocket()
{
  return d_socket;
}

Session Server::accept()
{
  ComboAddress remote;
  remote.sin4.sin_family = AF_INET6;
  socklen_t remlen = remote.getSocklen();

  int socket=-1;

  while((socket=::accept(s, (struct sockaddr *)&remote, &remlen))==-1) // repeat until we have a successful connect
    {
      //      L<<Logger::Error<<"accept() returned: "<<strerror(errno)<<endl;
      if(errno==EMFILE) {
        throw SessionException("Out of file descriptors - won't recover from that");
      }

    }

  Session session(socket, remote);
  return session;
}

void Server::asyncNewConnection()
{
  try {
    d_asyncNewConnectionCallback(accept());
  } catch (SessionException &e) {
    // we're running in a shared process/thread, so can't just terminate/abort.
    return;
  }
}

void Server::asyncWaitForConnections(FDMultiplexer* fdm, const newconnectioncb_t& callback)
{
  d_asyncNewConnectionCallback = callback;
  fdm->addReadFD(s, boost::bind(&Server::asyncNewConnection, this));
}

Server::Server(const string &localaddress, int port)
{
  d_local = ComboAddress(localaddress.empty() ? "0.0.0.0" : localaddress, port);
  s = socket(d_local.sin4.sin_family ,SOCK_STREAM,0);

  if(s < 0)
    throw SessionException(string("socket: ")+strerror(errno));

  Utility::setCloseOnExec(s);

  int tmp=1;
  if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, static_cast<unsigned>(sizeof tmp))<0)
    throw SessionException(string("Setsockopt failed: ")+strerror(errno));

  if(bind(s, (sockaddr*)&d_local, d_local.getSocklen())<0)
    throw SessionException("binding to "+d_local.toStringWithPort()+": "+strerror(errno));
  
  if(listen(s,128)<0)
    throw SessionException("listen: "+stringerror());
}

