/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2013  PowerDNS.COM BV

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
#ifndef SESSION_HH
#define SESSION_HH

#include <string>
#include <cerrno>

#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <strings.h>

#include "iputils.hh"
#include "pdnsexception.hh"
#include "mplexer.hh"

class SessionException: public PDNSException
{
public:
  SessionException(const string &reason) : PDNSException(reason){}
};

class SessionTimeoutException: public SessionException
{
public:
  SessionTimeoutException(const string &reason) : SessionException(reason){}
};

//! The Session class represents a TCP/IP session, which can either be created or run on an existing socket
class Session
{
public:
  bool put(const string &s);
  bool good();
  size_t read(char* buf, size_t len);

  Session(int s, ComboAddress r); //!< Start a session on an existing socket, and inform this class of the remotes name

  /** Create a session to a remote host and port. This function reads a timeout value from the ArgvMap class 
      and does a nonblocking connect to support this timeout. It should be noted that nonblocking connects 
      suffer from bad portability problems, so look here if you see weird problems on new platforms */
  Session(const string &remote, int port, int timeout=0); 

  Session(const Session &s); 
  Session();
  
  ~Session();
  int getSocket(); //!< return the filedescriptor for layering violations
  int close(); //!< close and disconnect the connection
  void setTimeout(unsigned int seconds);
private:
  int d_socket;
  ComboAddress d_remote;
  int d_timeout;
  bool d_good;
};

//! The server class can be used to create listening servers
class Server
{
public:
  Server(const string &localaddress, int port);
  ComboAddress d_local;

  Session accept(); //!< Call accept() in an endless loop to accept new connections

  typedef boost::function< void(Session) > newconnectioncb_t;
  void asyncWaitForConnections(FDMultiplexer* fdm, const newconnectioncb_t& callback);

private:
  int s;
  void asyncNewConnection();
  newconnectioncb_t d_asyncNewConnectionCallback;
};

#endif /* SESSION_HH */
