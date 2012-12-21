/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 2 as published
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef NAMESERVER_HH
#define NAMESERVER_HH

#ifndef WIN32
# include <poll.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <sys/time.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <netdb.h>

#endif // WIN32

#include <vector>
#include <boost/foreach.hpp>
#include "statbag.hh"
#include "namespaces.hh"

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
  DNSPacket *receive(DNSPacket *prefilled=0); //!< call this in a while or for(;;) loop to get packets
  static void send(DNSPacket *); //!< send a DNSPacket. Will call DNSPacket::truncate() if over 512 bytes
  
private:
  vector<int> d_sockets;
  void bindIPv4();
  void bindIPv6();
  vector<pollfd> d_rfds;
};




#endif
