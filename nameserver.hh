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
// $Id: nameserver.hh,v 1.4 2003/12/22 11:53:41 ahu Exp $
#ifndef NAMESERVER_HH
#define NAMESERVER_HH

#ifndef WIN32
# include <sys/select.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <sys/time.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <netdb.h>

#endif // WIN32

#include <vector>
#include "statbag.hh"
using namespace std;

/** This is the main class. It opens a socket on udp port 53 and waits for packets. Those packets can 
    be retrieved with the receive() member function, which returns a DNSPacket.

    Some sample code in main():
    \code
    typedef Distributor<DNSPacket,DNSPacket,PacketHandler> DNSDistributor;
    DNSDistributor D(6); // the big dispatcher!
    
    pthread_t qtid, atid;
    N=new UDPNameserver;
    
    pthread_create(&qtid,0,qthread,static_cast<void *>(&D)); // receives packets
    pthread_create(&atid,0,athread,static_cast<void *>(&D)); // sends packets
    \endcode

    Code for qthread:
    \code
    void *qthread(void *p)
    {
      DNSDistributor *D=static_cast<DNSDistributor *>(p);
    
      DNSPacket *P;
    
      while((P=N->receive())) // receive a packet
      {
         D->question(P); // and give to the distributor, they will delete it
      }
      return 0;
    }

    \endcode

*/

class UDPNameserver
{
public:
  UDPNameserver();  //!< Opens the socket
  inline DNSPacket *receive(DNSPacket *prefilled=0); //!< call this in a while or for(;;) loop to get packets
  static void send(DNSPacket *); //!< send a DNSPacket. Will call DNSPacket::truncate() if over 512 bytes
  
private:
  vector<int> d_sockets;
  void bindIPv4();
  void bindIPv6();
  fd_set d_rfds;
  int d_highfd;
  int* d_num_corrupt;
};

inline DNSPacket *UDPNameserver::receive(DNSPacket *prefilled)
{
  char remote[ 30 ];
  extern StatBag S;

  Utility::socklen_t addrlen;
  int len=-1;
  char mesg[513];
  Utility::sock_t sock=-1;

  memset( remote, 0, sizeof( remote ));
  addrlen=sizeof(remote);  
  if(d_sockets.size()>1) {
    fd_set rfds=d_rfds;
    
    select(d_highfd+1, &rfds, 0, 0,  0); // blocks

    for(vector<int>::const_iterator i=d_sockets.begin();i!=d_sockets.end();++i) {
      if(FD_ISSET(*i, &rfds)) {
	sock=*i;
	addrlen=sizeof(remote);
	
	len=0;
	if((len=recvfrom(sock,mesg,512,0,(sockaddr*) remote, &addrlen))<0) {
	  L<<Logger::Error<<"recvfrom gave error, ignoring: "<<strerror(errno)<<endl;
	  return 0;
	}
	break;
      }
    }
    if(sock==-1)
      throw AhuException("select betrayed us! (should not happen)");
  }
  else {
    sock=d_sockets[0];

    len=0;
    if((len=recvfrom(sock,mesg,512,0,(sockaddr*) remote, &addrlen))<0) {
      L<<Logger::Error<<"recvfrom gave error, ignoring: "<<strerror(errno)<<endl;
      return 0;
    }
  }
  
  DLOG(L<<"Received a packet " << len <<" bytes long from "<<inet_ntoa( reinterpret_cast< sockaddr_in * >( &remote )->sin_addr )<<endl);
  
  DNSPacket *packet;
  if(prefilled)  // they gave us a preallocated packet
    packet=prefilled;
  else
    packet=new DNSPacket; // don't forget to free it!
  packet->d_dt.set(); // timing
  packet->setSocket(sock);
  packet->setRemote((struct sockaddr *)remote, addrlen);
  if(packet->parse(mesg, len)<0) {
    (*d_num_corrupt)++;
    S.ringAccount("remotes-corrupt", packet->getRemote());

    if(!prefilled)
      delete packet;
    return 0; // unable to parse
  }
  
  return packet;
}



#endif
