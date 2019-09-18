/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef SSTUFF_HH
#define SSTUFF_HH

#include <string>
#include <sstream>
#include <iostream>
#include "iputils.hh"
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <stdexcept>

#include <boost/utility.hpp>
#include <csignal>
#include "namespaces.hh"
#include "namespaces.hh"


typedef int ProtocolType; //!< Supported protocol types

//! Representation of a Socket and many of the Berkeley functions available
class Socket : public boost::noncopyable
{
  Socket(int fd): d_socket(fd)
  {
  }

public:
  //! Construct a socket of specified address family and socket type.
  Socket(int af, int st, ProtocolType pt=0)
  {
    if((d_socket=socket(af, st, pt))<0)
      throw NetworkError(stringerror());
    setCloseOnExec(d_socket);
  }

  Socket(Socket&& rhs): d_buffer(std::move(rhs.d_buffer)), d_socket(rhs.d_socket)
  {
    rhs.d_socket = -1;
  }

  ~Socket()
  {
    try {
      if (d_socket != -1) {
        closesocket(d_socket);
      }
    }
    catch(const PDNSException& e) {
    }
  }

  //! If the socket is capable of doing so, this function will wait for a connection
  std::unique_ptr<Socket> accept()
  {
    struct sockaddr_in remote;
    socklen_t remlen=sizeof(remote);
    memset(&remote, 0, sizeof(remote));
    int s=::accept(d_socket, reinterpret_cast<sockaddr *>(&remote), &remlen);
    if(s<0) {
      if(errno==EAGAIN)
        return nullptr;

      throw NetworkError("Accepting a connection: "+stringerror());
    }

    return std::unique_ptr<Socket>(new Socket(s));
  }

  //! Get remote address
  bool getRemote(ComboAddress &remote) {
    socklen_t remotelen=sizeof(remote);
    return (getpeername(d_socket, reinterpret_cast<struct sockaddr *>(&remote), &remotelen) >= 0);
  }

  //! Check remote address against netmaskgroup ng
  bool acl(const NetmaskGroup &ng)
  {
    ComboAddress remote;
    if (getRemote(remote))
      return ng.match(remote);

    return false;
  }

  //! Set the socket to non-blocking
  void setNonBlocking()
  {
    ::setNonBlocking(d_socket);
  }

  //! Set the socket to blocking
  void setBlocking()
  {
    ::setBlocking(d_socket);
  }

  void setReuseAddr()
  {
    try {
      ::setReuseAddr(d_socket);
    } catch (const PDNSException &e) {
      throw NetworkError(e.reason);
    }
  }

  //! Bind the socket to a specified endpoint
  void bind(const ComboAddress &local, bool reuseaddr=true)
  {
    int tmp=1;
    if(reuseaddr && setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&tmp), sizeof tmp)<0)
      throw NetworkError("Setsockopt failed: "+stringerror());

    if(::bind(d_socket, reinterpret_cast<const struct sockaddr *>(&local), local.getSocklen())<0)
      throw NetworkError("While binding: "+stringerror());
  }

  //! Connect the socket to a specified endpoint
  void connect(const ComboAddress &ep, int timeout=0)
  {
    SConnectWithTimeout(d_socket, ep, timeout);
  }


  //! For datagram sockets, receive a datagram and learn where it came from
  /** For datagram sockets, receive a datagram and learn where it came from
      \param dgram Will be filled with the datagram
      \param ep Will be filled with the origin of the datagram */
  void recvFrom(string &dgram, ComboAddress &ep)
  {
    socklen_t remlen = sizeof(ep);
    ssize_t bytes;
    d_buffer.resize(s_buflen);
    if((bytes=recvfrom(d_socket, &d_buffer[0], s_buflen, 0, reinterpret_cast<sockaddr *>(&ep) , &remlen)) <0)
      throw NetworkError("After recvfrom: "+stringerror());
    
    dgram.assign(d_buffer, 0, static_cast<size_t>(bytes));
  }

  bool recvFromAsync(string &dgram, ComboAddress &ep)
  {
    struct sockaddr_in remote;
    socklen_t remlen = sizeof(remote);
    ssize_t bytes;
    d_buffer.resize(s_buflen);
    if((bytes=recvfrom(d_socket, &d_buffer[0], s_buflen, 0, reinterpret_cast<sockaddr *>(&remote), &remlen))<0) {
      if(errno!=EAGAIN) {
        throw NetworkError("After async recvfrom: "+stringerror());
      }
      else {
        return false;
      }
    }
    dgram.assign(d_buffer, 0, static_cast<size_t>(bytes));
    return true;
  }


  //! For datagram sockets, send a datagram to a destination
  void sendTo(const char* msg, size_t len, const ComboAddress &ep)
  {
    if(sendto(d_socket, msg, len, 0, reinterpret_cast<const sockaddr *>(&ep), ep.getSocklen())<0)
      throw NetworkError("After sendto: "+stringerror());
  }

  //! For connected datagram sockets, send a datagram
  void send(const std::string& msg)
  {
    if(::send(d_socket, msg.c_str(), msg.size(), 0)<0)
      throw NetworkError("After send: "+stringerror());
  }

  
  /** For datagram sockets, send a datagram to a destination
      \param dgram The datagram
      \param ep The intended destination of the datagram */
  void sendTo(const string &dgram, const ComboAddress &ep)
  {
    sendTo(dgram.c_str(), dgram.length(), ep);
  }


  //! Write this data to the socket, taking care that all bytes are written out 
  void writen(const string &data)
  {
    if(data.empty())
      return;

    size_t toWrite=data.length();
    ssize_t res;
    const char *ptr=data.c_str();

    do {
      res=::send(d_socket, ptr, toWrite, 0);
      if(res<0) 
        throw NetworkError("Writing to a socket: "+stringerror());
      if(!res)
        throw NetworkError("EOF on socket");
      toWrite -= static_cast<size_t>(res);
      ptr += static_cast<size_t>(res);
    } while(toWrite);

  }

  //! tries to write toWrite bytes from ptr to the socket
  /** tries to write toWrite bytes from ptr to the socket, but does not make sure they al get written out
      \param ptr Location to write from
      \param toWrite number of bytes to try
  */
  size_t tryWrite(const char *ptr, size_t toWrite)
  {
    ssize_t res;
    res=::send(d_socket,ptr,toWrite,0);
    if(res==0)
      throw NetworkError("EOF on writing to a socket");

    if(res>0)
      return res;

    if(errno==EAGAIN)
      return 0;
    
    throw NetworkError("Writing to a socket: "+stringerror());
  }

  //! Writes toWrite bytes from ptr to the socket
  /** Writes toWrite bytes from ptr to the socket. Returns how many bytes were written */
  size_t write(const char *ptr, size_t toWrite)
  {
    ssize_t res;
    res=::send(d_socket,ptr,toWrite,0);
    if(res<0) {
      throw NetworkError("Writing to a socket: "+stringerror());
    }
    return res;
  }

  void writenWithTimeout(const void *buffer, size_t n, int timeout)
  {
    size_t bytes=n;
    const char *ptr = reinterpret_cast<const char*>(buffer);
    ssize_t ret;
    while(bytes) {
      ret=::write(d_socket, ptr, bytes);
      if(ret < 0) {
        if(errno==EAGAIN) {
          ret=waitForRWData(d_socket, false, timeout, 0);
          if(ret < 0)
            throw NetworkError("Waiting for data write");
          if(!ret)
            throw NetworkError("Timeout writing data");
          continue;
        }
        else
          throw NetworkError("Writing data: "+stringerror());
      }
      if(!ret) {
        throw NetworkError("Did not fulfill TCP write due to EOF");
      }

      ptr += static_cast<size_t>(ret);
      bytes -= static_cast<size_t>(ret);
    }
  }

  //! reads one character from the socket 
  int getChar()
  {
    char c;

    ssize_t res=::recv(d_socket,&c,1,0);
    if(res)
      return c;
    return -1;
  }

  void getline(string &data)
  {
    data="";
    int c;
    while((c=getChar())!=-1) {
      data+=(char)c;
      if(c=='\n')
        break;
    }
  }

  //! Reads a block of data from the socket to a string
  void read(string &data)
  {
    d_buffer.resize(s_buflen);
    ssize_t res=::recv(d_socket, &d_buffer[0], s_buflen, 0);
    if(res<0) 
      throw NetworkError("Reading from a socket: "+stringerror());
    data.assign(d_buffer, 0, static_cast<size_t>(res));
  }

  //! Reads a block of data from the socket to a block of memory
  size_t read(char *buffer, size_t bytes)
  {
    ssize_t res=::recv(d_socket, buffer, bytes, 0);
    if(res<0) 
      throw NetworkError("Reading from a socket: "+stringerror());
    return static_cast<size_t>(res);
  }

  ssize_t readWithTimeout(char* buffer, size_t n, int timeout)
  {
    int err = waitForRWData(d_socket, true, timeout, 0);

    if(err == 0)
      throw NetworkError("timeout reading");
    if(err < 0)
      throw NetworkError("nonblocking read failed: "+stringerror());

    return read(buffer, n);
  }

  //! Sets the socket to listen with a default listen backlog of 10 pending connections 
  void listen(unsigned int length=10)
  {
    if(::listen(d_socket,length)<0)
      throw NetworkError("Setting socket to listen: "+stringerror());
  }

  //! Returns the internal file descriptor of the socket
  int getHandle() const
  {
    return d_socket;
  }
  
private:
  static const size_t s_buflen{4096};
  std::string d_buffer;
  int d_socket;
};


#endif
