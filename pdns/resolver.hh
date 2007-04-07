/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2006  PowerDNS.COM BV

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

#include <string>
#include <vector>
#include <sys/types.h>
#include "iputils.hh"
#ifndef WIN32
# include <netdb.h> 
# include <unistd.h>
# include <sys/time.h>
# include <sys/uio.h>
# include <fcntl.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# undef res_mkquery
#endif // WIN32

#include "ahuexception.hh"
#include "dns.hh"
using namespace std;

class ResolverException : public AhuException
{
public:
  ResolverException(const string &reason) : AhuException(reason){}
};

//! Resolver class 
class Resolver
{
public:
  Resolver();
  ~Resolver();
  string i;

  typedef vector<DNSResourceRecord> res_t;
  void makeSocket(int type);
  void makeUDPSocket();
  void makeTCPSocket(const string &ip, uint16_t port=53);
  int notify(int sock, const string &domain, const string &ip, uint16_t id);
  int resolve(const string &ip, const char *domain, int type);
  void sendResolve(const string &ip, const char *domain, int type);

  int receiveResolve(struct sockaddr* fromaddr, Utility::socklen_t addrlen);
  char* sendReceive(const string &ip, uint16_t remotePort, const char *packet, int length, unsigned int *replylen);
  void getSoaSerial(const string &, const string &, uint32_t *);
  int axfrChunk(Resolver::res_t &res);
  vector<DNSResourceRecord> result();
  
  void setRemote(const string &remote);
  int axfr(const string &ip, const char *domain);
  
private:
  void timeoutReadn(char *buffer, int bytes);
  int d_sock;
  unsigned char *d_buf;
  int getLength();
  int d_len;
  int d_soacount;
  string d_domain;
  int d_type;
  int d_timeout;
  uint32_t d_ip;
  uint16_t d_randomid;
  bool d_inaxfr;
  ComboAddress d_toaddr;
};

