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
#include "misc.hh"
#include <vector>
#include <sstream>
#include <errno.h>
#include <cstring>
#include <iostream>

#include <iomanip>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ahuexception.hh"
#include <sys/types.h>

#ifndef WIN32
# include <sys/param.h>
# include <netdb.h>
# include <sys/time.h>
# include <time.h>
# include <netinet/in.h>
# include <unistd.h>
#else
# include <time.h>
#endif // WIN32

#include "utility.hh"

string nowTime()
{
  time_t now=time(0);
  string t=ctime(&now);
  chomp(t,"\n");
  return t;
}

u_int16_t getShort(const unsigned char *p)
{
  return p[0] * 256 + p[1];
}


u_int16_t getShort(const char *p)
{
  return getShort((const unsigned char *)p);
}

u_int32_t getLong(const unsigned char* p)
{
  return (p[0]<<24) + (p[1]<<16) + (p[2]<<8) + p[3];
}

u_int32_t getLong(const char* p)
{
  return getLong((unsigned char *)p);
}



/** strips a domain suffix from a domain, returns true if it stripped */
bool stripDomainSuffix(string *qname, const string &domain)
{
  if(!endsOn(*qname, domain))
    return false;

  if(toLower(*qname)==toLower(domain))
    *qname="@";
  else {
    if((*qname)[qname->size()-domain.size()-1]!='.')
      return false;

    qname->resize(qname->size()-domain.size()-1);
  }
  return true;
}

/** Chops off the start of a domain, so goes from 'www.ds9a.nl' to 'ds9a.nl' to ''. Return zero on the empty string */
bool chopOff(string &domain)
{
  if(domain.empty())
    return false;

  string::size_type fdot=domain.find('.');

  if(fdot==string::npos) 
    domain="";
  else 
    domain=domain.substr(fdot+1);
  return true;
}

/** does domain end on suffix? Is smart about "wwwds9a.nl" "ds9a.nl" not matching */
bool endsOn(const string &domain, const string &suffix) 
{
  if(toLower(domain)==toLower(suffix) || suffix.empty())
    return true;
  if(domain.size()<=suffix.size())
    return false;
  return (toLower(domain.substr(domain.size()-suffix.size()-1,suffix.size()+1))=="."+toLower(suffix));
}


int sendData(const char *buffer, int replen, int outsock)
{
  u_int16_t nlen=htons(replen);
  Utility::iovec iov[2];
  iov[0].iov_base=(char*)&nlen;
  iov[0].iov_len=2;
  iov[1].iov_base=(char*)buffer;
  iov[1].iov_len=replen;
  int ret=Utility::writev(outsock,iov,2);

  if(ret<0) {
    return -1;
  }
  if(ret!=replen+2) {
    return -1;
  }
  return 0;
}


void parseService(const string &descr, ServiceTuple &st)
{

  vector<string>parts;
  stringtok(parts,descr,":");
  if(parts.empty())
    throw AhuException("Unable to parse '"+descr+"' as a service");
  st.host=parts[0];
  if(parts.size()>1)
    st.port=atoi(parts[1].c_str());
}


int waitForData(int fd, int seconds)
{
  struct timeval tv;
  int ret;

  tv.tv_sec   = seconds;
  tv.tv_usec  = 0;

  fd_set readfds;
  FD_ZERO( &readfds );
  FD_SET( fd, &readfds );

  ret = select( fd + 1, &readfds, NULL, NULL, &tv );
  if ( ret == -1 )
  {
    ret = -1;
    errno = ETIMEDOUT;
  }

  return ret;
}


string humanDuration(time_t passed)
{
  ostringstream ret;
  if(passed<60)
    ret<<passed<<" seconds";
  else if(passed<3600)
    ret<<setprecision(2)<<passed/60.0<<" minutes";
  else if(passed<86400)
    ret<<setprecision(3)<<passed/3600.0<<" hours";
  else if(passed<(86400*30.41))
    ret<<setprecision(3)<<passed/86400.0<<" days";
  else
    ret<<setprecision(3)<<passed/(86400*30.41)<<" months";

  return ret.str();
}

DTime::DTime()
{
//  set(); // saves lots of gettimeofday calls
}

DTime::DTime(const DTime &dt)
{
  d_set=dt.d_set;
}

time_t DTime::time()
{
  return d_set.tv_sec;
}

const string unquotify(const string &item)
{
  if(item.size()<2)
    return item;

  string::size_type bpos=0, epos=item.size();

  if(item[0]=='"') 
    bpos=1;

  if(item[epos-1]=='"')
    epos-=1;

  return item.substr(bpos,epos-bpos);
}

void stripLine(string &line)
{
  string::size_type pos=line.find_first_of("\r\n");
  if(pos!=string::npos) {
    line.resize(pos);
  }
}

string urlEncode(const string &text)
{
  string ret;
  for(string::const_iterator i=text.begin();i!=text.end();++i)
    if(*i==' ')ret.append("%20");
    else ret.append(1,*i);
  return ret;
}

string getHostname()
{
#ifdef WIN32
# define MAXHOSTNAMELEN 1025
#endif // WIN32

  char tmp[MAXHOSTNAMELEN];
  if(gethostname(tmp, MAXHOSTNAMELEN))
    return "UNKNOWN";

  return tmp;
}

string itoa(int i)
{
  ostringstream o;
  o<<i;
  return o.str();
}

string stringerror()
{
  return strerror(errno);
}

void cleanSlashes(string &str)
{
  string::const_iterator i;
  string out;
  for(i=str.begin();i!=str.end();++i) {
    if(*i=='/' && i!=str.begin() && *(i-1)=='/')
      continue;
    out.append(1,*i);
  }
  str=out;
}


bool IpToU32(const string &str, u_int32_t *ip)
{
  struct in_addr inp;
  if(Utility::inet_aton(str.c_str(), &inp)) {
    *ip=inp.s_addr;
    return true;
  }
  return false;
}

const string sockAddrToString(struct sockaddr_in *remote, Utility::socklen_t socklen) 
{    
  if(socklen==sizeof(struct sockaddr_in)) {
    struct sockaddr_in sip;
    memcpy(&sip,(struct sockaddr_in*)remote,sizeof(sip));
    return inet_ntoa(sip.sin_addr);
  }
#ifdef HAVE_IPV6
  else {
    char tmp[128];
    
    if(!Utility::inet_ntop(AF_INET6, ( const char * ) &((struct sockaddr_in6 *)remote)->sin6_addr, tmp, sizeof(tmp)))
      return "IPv6 untranslateable";

    return tmp;
  }
#endif

  return "untranslateable";
}
