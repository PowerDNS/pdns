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
#ifndef NAMESERVER_HH
#define NAMESERVER_HH

#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>

#include "statbag.hh"
#include "namespaces.hh"
#include "dnspacket.hh"
#include "responsestats.hh"

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

#ifdef __linux__
#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif
#endif

class UDPNameserver
{
public:
  UDPNameserver( bool additional_socket = false );  //!< Opens the socket
  bool receive(DNSPacket& packet, std::string& buffer); //!< call this in a while or for(;;) loop to get packets
  void send(DNSPacket&); //!< send a DNSPacket. Will call DNSPacket::truncate() if over 512 bytes
  inline bool canReusePort() {
#ifdef SO_REUSEPORT
    return d_can_reuseport;
#else
    return false;
#endif
  };
  
private:
  bool d_additional_socket;
#ifdef SO_REUSEPORT
  bool d_can_reuseport;
#endif
  vector<int> d_sockets;
  void bindIPv4();
  void bindIPv6();
  vector<pollfd> d_rfds;
};

bool AddressIsUs(const ComboAddress& remote);

extern ResponseStats g_rs;

#endif
