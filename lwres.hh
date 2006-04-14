/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2005 PowerDNS.COM BV

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

#ifndef PDNS_LWRES_HH
#define PDNS_LWRES_HH
#include <string>
#include <vector>
#include <sys/types.h>
#include "misc.hh"

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

int asendto(const char *data, int len, int flags, struct sockaddr *toaddr, int addrlen, int id, int* fd);
int arecvfrom(char *data, int len, int flags, struct sockaddr *toaddr, Utility::socklen_t *addrlen, int *d_len, int id, const string& domain, int fd);

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

  int asyncresolve(uint32_t ip, const string& domain, int type, bool doTCP, struct timeval* now);
  vector<DNSResourceRecord> result();
  int d_rcode;
  bool d_aabit, d_tcbit;
  uint32_t d_usec;
private:
  int d_sock;
  unsigned char *d_buf;
  int getLength();
  int d_len;
  int d_soacount;
  string d_domain;
  int d_type;
  int d_timeout;
  uint32_t d_ip;
  bool d_inaxfr;
  int d_bufsize;
};

#endif // PDNS_LWRES_HH
