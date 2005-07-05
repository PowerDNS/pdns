#ifndef SSTUFF_HH
#define SSTUFF_HH

#include <string>
#include <sstream>
#include <iostream>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <stdexcept>
#include <boost/shared_ptr.hpp>
#include <csignal>
using namespace std;
using namespace boost;


class NetworkError : public runtime_error
{
public:
  NetworkError(string why="Network Error") : runtime_error(why.c_str())
  {}
  NetworkError(char *why="Network Error") : runtime_error(why)
  {}
};


//! Representation of an IP Address
class IPAddress
{
public:
  u_int32_t byte; 

  //! The default IPAddress is 0.0.0.0
  IPAddress()
  {
    byte=0;
  }
  //! Construct an IP address based on a string representation of one
  IPAddress(const string &remote)
  {
    struct in_addr addr;
    if(!inet_aton(remote.c_str(), &addr))
      throw NetworkError("Could not convert '"+remote+"' to an IP address");
    byte=addr.s_addr;
  }

  //! Return an IP address as a printable string
  string asString() const
  {
    ostringstream o;
    const unsigned char *n=reinterpret_cast<const unsigned char*>(&byte);
    o<<(unsigned int)*n++<<".";
    o<<(unsigned int)*n++<<".";
    o<<(unsigned int)*n++<<".";
    o<<(int)*n++;
    return o.str();
  }
};

typedef u_int16_t IPPort;

//! Defines an IP Endpoint which consists of an IP address and a port number
class IPEndpoint
{
public:

  IPEndpoint(){}   //!< Empty IPEndpoint
  IPEndpoint(const string &remote, IPPort aport=0) : address(remote), port(aport){} //!< Construct a fully configured endpoint
  IPAddress address;
  IPPort port;
  enum PortTypes {ANY=0};
};


enum AddressFamily {InterNetwork=AF_INET}; //!< Supported address families
enum SocketType {Datagram=SOCK_DGRAM,Stream=SOCK_STREAM}; //!< Supported socket families
typedef int ProtocolType; //!< Supported protocol types

//! Representation of a Socket and many of the Berkeley functions available
class Socket
{
private:
  Socket(const Socket &);
  Socket &operator=(const Socket &);

  Socket(int fd)
  {
    d_buflen=1024;
    d_buffer=new char[d_buflen];
    d_socket=fd;
  }
public:
  //! Construct a socket of specified AddressFamily and SocketType.
  Socket(AddressFamily af, SocketType st, ProtocolType pt=0)
  {
    d_family=af;
    if((d_socket=socket(af,st, pt))<0)
      throw NetworkError(strerror(errno));
    d_buflen=1024;
    d_buffer=new char[d_buflen];
  }

  ~Socket()
  {
    ::close(d_socket);
    delete[] d_buffer;
  }

  //! If the socket is capable of doing so, this function will wait for a connection
  Socket *accept()
  {
    struct sockaddr_in remote;
    socklen_t remlen=sizeof(remote);
    memset(&remote, 0, sizeof(remote));
    int s=::accept(d_socket,(sockaddr *)&remote, &remlen);
    if(s<0) {
      if(errno==EAGAIN)
	return 0;

      throw NetworkError("Accepting a connection: "+string(strerror(errno)));
    }

    return new Socket(s);
  }

  //! Set the socket to non-blocking
  void setNonBlocking()
  {
    int flags=fcntl(d_socket,F_GETFL,0);    
    if(flags<0 || fcntl(d_socket, F_SETFL,flags|O_NONBLOCK) <0)
      throw NetworkError("Setting socket to nonblocking: "+string(strerror(errno)));
  }

  //! Bind the socket to a specified endpoint
  void bind(const IPEndpoint &ep)
  {
    struct sockaddr_in local;
    memset(reinterpret_cast<char *>(&local),0,sizeof(local));
    local.sin_family=d_family;
    local.sin_addr.s_addr=ep.address.byte;
    local.sin_port=htons(ep.port);
    
    int tmp=1;
    if(setsockopt(d_socket,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0)
      throw NetworkError(string("Setsockopt failed: ")+strerror(errno));

    if(::bind(d_socket,(struct sockaddr *)&local,sizeof(local))<0)
      throw NetworkError(strerror(errno));
  }

  //! Connect the socket to a specified endpoint
  void connect(const IPEndpoint &ep)
  {
    struct sockaddr_in remote;
    memset(reinterpret_cast<char *>(&remote),0,sizeof(remote));
    remote.sin_family=d_family;
    remote.sin_addr.s_addr=ep.address.byte;
    remote.sin_port=htons(ep.port);
    
    if(::connect(d_socket,(struct sockaddr *)&remote,sizeof(remote)) < 0 && errno != EINPROGRESS)
      throw NetworkError(strerror(errno));
  }


  //! For datagram sockets, receive a datagram and learn where it came from
  /** For datagram sockets, receive a datagram and learn where it came from
      \param dgram Will be filled with the datagram
      \param ep Will be filled with the origin of the datagram */
  void recvFrom(string &dgram, IPEndpoint &ep)
  {
    struct sockaddr_in remote;
    socklen_t remlen=sizeof(remote);
    int bytes;
    if((bytes=recvfrom(d_socket, d_buffer, d_buflen, 0, (sockaddr *)&remote, &remlen))<0)
      throw NetworkError(strerror(errno));
    
    dgram.assign(d_buffer,bytes);
    ep.address.byte=remote.sin_addr.s_addr;
    ep.port=ntohs(remote.sin_port);
  }

  bool recvFromAsync(string &dgram, IPEndpoint &ep)
  {
    struct sockaddr_in remote;
    socklen_t remlen=sizeof(remote);
    int bytes;
    if((bytes=recvfrom(d_socket, d_buffer, d_buflen, 0, (sockaddr *)&remote, &remlen))<0)
      if(errno!=EAGAIN)
	throw NetworkError(strerror(errno));
      else
	return false;
    
    dgram.assign(d_buffer,bytes);
    ep.address.byte=remote.sin_addr.s_addr;
    ep.port=ntohs(remote.sin_port);
    return true;
  }


  //! For datagram sockets, send a datagram to a destination
  /** For datagram sockets, send a datagram to a destination
      \param dgram The datagram
      \param ep The intended destination of the datagram */
  void sendTo(const string &dgram, const IPEndpoint &ep)
  {
    struct sockaddr_in remote;
    remote.sin_family=d_family;
    remote.sin_addr.s_addr=ep.address.byte;
    remote.sin_port=ntohs(ep.port);

    if(sendto(d_socket, dgram.c_str(), dgram.size(), 0, (sockaddr *)&remote, sizeof(remote))<0)
      throw NetworkError(strerror(errno));
  }

  //! Write this data to the socket, taking care that all bytes are written out 
  void writen(const string &data)
  {
    if(data.empty())
      return;

    int toWrite=data.length();
    int res;
    const char *ptr=data.c_str();

    do {
      res=::write(d_socket,ptr,toWrite);
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
    res=::write(d_socket,ptr,toWrite);
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
    res=::write(d_socket,ptr,toWrite);
    if(res<0) {
      throw NetworkError("Writing to a socket: "+string(strerror(errno)));
    }
    return res;
  }


  //! reads one character from the socket 
  int getChar()
  {
    char c;

    int res=::read(d_socket,&c,1);
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
    int res=::read(d_socket,d_buffer,d_buflen);
    if(res<0) 
      throw NetworkError("Reading from a socket: "+string(strerror(errno)));
    data.assign(d_buffer,res);
  }

  //! Reads a block of data from the socket to a block of memory
  int read(char *buffer, int bytes)
  {
    int res=::read(d_socket,buffer,bytes);
    if(res<0) 
      throw NetworkError("Reading from a socket: "+string(strerror(errno)));
    return res;

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
  int d_socket;
  char *d_buffer;
  int d_buflen;
  int d_family;
};

//! Convenience class built on top of Socket for writing UDP servers
class UDPListener
{
public:
  //! Constructor taking an IPEndpoint describing on what addresses to listen
  UDPListener(const IPEndpoint &ep)
  {
    d_ep=ep;
    initSocket();
  }
  //! Constructor taking only a port number, binding to all interfaces
  UDPListener(IPPort port)
  {
    d_ep.address.byte=0; // =IPAddress::ANY;
    d_ep.port=port;
    initSocket();
  }
  //! For clients mostly, binds to all interfaces using a kernel assigned port number
  UDPListener()
  {
    d_ep.address.byte=0; // =IPEndpoint::ANY;
    d_ep.port=0;
    initSocket();
  }
  ~UDPListener()
  {
    delete d_socket;
  }
  //! Returns a datagram and reports its origin
  void recvFrom(string &dgram, IPEndpoint &remote)
  {
    d_socket->recvFrom(dgram,remote);
  }

  //! Sends a datagram to a remote
  void sendTo(const string &dgram, const IPEndpoint &remote)
  {
    d_socket->sendTo(dgram,remote);
  }

private:
  void initSocket()
  {
    d_socket=new Socket(InterNetwork, Datagram);
    d_socket->bind(d_ep);
  }

private:
  UDPListener(const UDPListener &);
  UDPListener &operator=(const UDPListener &);
  IPEndpoint d_ep;
  Socket *d_socket;

};

#endif
