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


class NetworkError : public runtime_error
{
public:
  NetworkError(const string& why="Network Error") : runtime_error(why.c_str())
  {}
  NetworkError(const char *why="Network Error") : runtime_error(why)
  {}
};


typedef int ProtocolType; //!< Supported protocol types

//! Representation of a Socket and many of the Berkeley functions available
class Socket : public boost::noncopyable
{
  Socket(int fd)
  {
    d_socket = fd;
    d_buflen=4096;
    d_buffer=new char[d_buflen];
  }

public:
  //! Construct a socket of specified address family and socket type.
  Socket(int af, int st, ProtocolType pt=0)
  {
    if((d_socket=(int)socket(af,st, pt))<0)
      throw NetworkError(strerror(errno));
    setCloseOnExec(d_socket);

    d_buflen=4096;
    d_buffer=new char[d_buflen];
  }

  ~Socket()
  {
    closesocket(d_socket);
    delete[] d_buffer;
  }

  //! If the socket is capable of doing so, this function will wait for a connection
  Socket *accept()
  {
    struct sockaddr_in remote;
    socklen_t remlen=sizeof(remote);
    memset(&remote, 0, sizeof(remote));
    int s=(int)::accept(d_socket,(sockaddr *)&remote, &remlen);
    if(s<0) {
      if(errno==EAGAIN)
        return 0;

      throw NetworkError("Accepting a connection: "+string(strerror(errno)));
    }

    return new Socket(s);
  }

  //! Get remote address
  bool getRemote(ComboAddress &remote) {
    socklen_t remotelen=sizeof(remote);
    return (getpeername(d_socket, (struct sockaddr *)&remote, &remotelen) >= 0);
  }

  //! Check remote address aganst netmaskgroup ng
  bool acl(NetmaskGroup &ng)
  {
    ComboAddress remote;
    if (getRemote(remote))
      return ng.match((ComboAddress *) &remote);

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
    int tmp = 1;
    if (setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, static_cast<unsigned>(sizeof tmp))<0)
      throw NetworkError(string("Setsockopt failed: ")+strerror(errno));
  }

  //! Bind the socket to a specified endpoint
  void bind(const ComboAddress &local)
  {
    int tmp=1;
    if(setsockopt(d_socket, SOL_SOCKET, SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
      throw NetworkError(string("Setsockopt failed: ")+strerror(errno));

    if(::bind(d_socket,(struct sockaddr *)&local, local.getSocklen())<0)
      throw NetworkError("While binding: "+string(strerror(errno)));
  }

#if 0
  //! Bind the socket to a specified endpoint
  void bind(const ComboAddress &ep)
  {
    ComboAddress local;
    memset(reinterpret_cast<char *>(&local),0,sizeof(local));
    local.sin_family=d_family;
    local.sin_addr.s_addr=ep.address.byte;
    local.sin_port=htons(ep.port);
    
    bind(local);
  }
#endif
  //! Connect the socket to a specified endpoint
  void connect(const ComboAddress &ep)
  {
    if(::connect(d_socket,(struct sockaddr *)&ep, ep.getSocklen()) < 0 && errno != EINPROGRESS)
      throw NetworkError("While connecting: "+string(strerror(errno)));
  }


  //! For datagram sockets, receive a datagram and learn where it came from
  /** For datagram sockets, receive a datagram and learn where it came from
      \param dgram Will be filled with the datagram
      \param ep Will be filled with the origin of the datagram */
  void recvFrom(string &dgram, ComboAddress &ep)
  {
    socklen_t remlen=sizeof(ep);
    int bytes;
    if((bytes=recvfrom(d_socket, d_buffer, d_buflen, 0, (sockaddr *)&ep , &remlen)) <0)
      throw NetworkError("After recvfrom: "+string(strerror(errno)));
    
    dgram.assign(d_buffer,bytes);
  }

  bool recvFromAsync(string &dgram, ComboAddress &ep)
  {
    struct sockaddr_in remote;
    socklen_t remlen=sizeof(remote);
    int bytes;
    if((bytes=recvfrom(d_socket, d_buffer, d_buflen, 0, (sockaddr *)&remote, &remlen))<0) {
      if(errno!=EAGAIN) {
        throw NetworkError("After async recvfrom: "+string(strerror(errno)));
      }
      else {
        return false;
      }
    }
    dgram.assign(d_buffer,bytes);
    return true;
  }


  //! For datagram sockets, send a datagram to a destination
  void sendTo(const char* msg, unsigned int len, const ComboAddress &ep)
  {
    if(sendto(d_socket, msg, len, 0, (sockaddr *)&ep, ep.getSocklen())<0)
      throw NetworkError("After sendto: "+string(strerror(errno)));
  }

  //! For connected datagram sockets, send a datagram
  void send(const std::string& msg)
  {
    if(::send(d_socket, msg.c_str(), msg.size(), 0)<0)
      throw NetworkError("After send: "+string(strerror(errno)));
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

    int toWrite=(int)data.length();
    int res;
    const char *ptr=data.c_str();

    do {
      res=::send(d_socket, ptr, toWrite, 0);
      if(res<0) 
        throw NetworkError("Writing to a socket: "+string(strerror(errno)));
      if(!res)
        throw NetworkError("EOF on socket");
      toWrite-=res;
      ptr+=res;
    }while(toWrite);

  }

  //! tries to write toWrite bytes from ptr to the socket
  /** tries to write toWrite bytes from ptr to the socket, but does not make sure they al get written out
      \param ptr Location to write from
      \param toWrite number of bytes to try
  */
  unsigned int tryWrite(const char *ptr, int toWrite)
  {
    int res;
    res=::send(d_socket,ptr,toWrite,0);
    if(res==0)
      throw NetworkError("EOF on writing to a socket");

    if(res>0)
      return res;

    if(errno==EAGAIN)
      return 0;
    
    throw NetworkError("Writing to a socket: "+string(strerror(errno)));
  }

  //! Writes toWrite bytes from ptr to the socket
  /** Writes toWrite bytes from ptr to the socket. Returns how many bytes were written */
  unsigned int write(const char *ptr, int toWrite)
  {
    int res;
    res=::send(d_socket,ptr,toWrite,0);
    if(res<0) {
      throw NetworkError("Writing to a socket: "+string(strerror(errno)));
    }
    return res;
  }

  void writenWithTimeout(const void *buffer, unsigned int n, int timeout)
  {
    unsigned int bytes=n;
    const char *ptr = (char*)buffer;
    int ret;
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

      ptr += ret;
      bytes -= ret;
    }
  }

  //! reads one character from the socket 
  int getChar()
  {
    char c;

    int res=::recv(d_socket,&c,1,0);
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
    int res=::recv(d_socket,d_buffer,d_buflen,0);
    if(res<0) 
      throw NetworkError("Reading from a socket: "+string(strerror(errno)));
    data.assign(d_buffer,res);
  }

  //! Reads a block of data from the socket to a block of memory
  int read(char *buffer, int bytes)
  {
    int res=::recv(d_socket,buffer,bytes,0);
    if(res<0) 
      throw NetworkError("Reading from a socket: "+string(strerror(errno)));
    return res;
  }

  int readWithTimeout(char* buffer, int n, int timeout)
  {
    int err = waitForRWData(d_socket, true, timeout, 0);

    if(err == 0)
      throw NetworkError("timeout reading");
    if(err < 0)
      throw NetworkError("nonblocking read failed: "+string(strerror(errno)));

    return read(buffer, n);
  }

  //! Sets the socket to listen with a default listen backlog of 10 bytes 
  void listen(unsigned int length=10)
  {
    if(::listen(d_socket,length)<0)
      throw NetworkError("Setting socket to listen: "+string(strerror(errno)));
  }

  //! Returns the internal file descriptor of the socket
  int getHandle() const
  {
    return d_socket;
  }
  
private:
  char *d_buffer;
  int d_socket;
  int d_buflen;
};


#endif
