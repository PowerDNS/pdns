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

#ifndef PDNS_LWRES_HH
#define PDNS_LWRES_HH
#include <string>
#include <vector>
#include <sys/types.h>

#ifndef WIN32

# include <arpa/nameser.h>
# include <resolv.h>
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

int asendto(const char *data, int len, int flags, struct sockaddr *toaddr, int addrlen, int id);
int arecvfrom(char *data, int len, int flags, struct sockaddr *toaddr, socklen_t *addrlen, int *d_len, int id);

class LWResException : public AhuException
{
public:
  LWResException(const string &reason) : AhuException(reason){}
};

//! LWRes class 
class LWRes
{
public:
  LWRes();
  ~LWRes();
  string i;

  typedef vector<DNSResourceRecord> res_t;

  int asyncresolve(const string &ip, const char *domain, int type);
  vector<DNSResourceRecord> result(bool &aabit);
  int d_rcode;
private:
  int d_sock;
  unsigned char *d_buf;
  int getLength();
  int d_len;
  int d_soacount;
  string d_domain;
  int d_type;
  int d_timeout;
  u_int32_t d_ip;
  bool d_inaxfr;
};

#endif // PDNS_LWRES_HH
