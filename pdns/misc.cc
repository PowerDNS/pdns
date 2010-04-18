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

#ifndef WIN32
#include <sys/param.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>
#endif // WIN32

#include "misc.hh"
#include <vector>
#include <sstream>
#include <errno.h>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <boost/optional.hpp>
#include <poll.h>
#include <iomanip>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ahuexception.hh"
#include <sys/types.h>
#include "utility.hh"
#include <boost/algorithm/string.hpp>

bool g_singleThreaded;

int writen2(int fd, const void *buf, size_t count)
{
  const char *ptr = (char*)buf;
  const char *eptr = ptr + count;
  
  int res;
  while(ptr != eptr) {
    res = ::write(fd, ptr, eptr - ptr);
    if(res < 0) {
      if (errno == EAGAIN)
        throw std::runtime_error("used writen2 on non-blocking socket, got EAGAIN");
      else
        unixDie("failed in writen2");
    }
    else if (res == 0)
      throw std::runtime_error("could not write all bytes, got eof in writen2");
    
    ptr += res;
  }
  
  return count;
}


string nowTime()
{
  time_t now=time(0);
  string t=ctime(&now);
  boost::trim_right(t);
  return t;
}

uint16_t getShort(const unsigned char *p)
{
  return p[0] * 256 + p[1];
}


uint16_t getShort(const char *p)
{
  return getShort((const unsigned char *)p);
}

uint32_t getLong(const unsigned char* p)
{
  return (p[0]<<24) + (p[1]<<16) + (p[2]<<8) + p[3];
}

uint32_t getLong(const char* p)
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

/** Chops off the start of a domain, so goes from 'www.ds9a.nl' to 'ds9a.nl' to 'nl' to ''. Return zero on the empty string */
bool chopOff(string &domain) 
{
  if(domain.empty())
    return false;

  string::size_type fdot=domain.find('.');

  if(fdot==string::npos) 
    domain="";
  else {
    string::size_type remain = domain.length() - (fdot + 1);
    char tmp[remain];
    memcpy(tmp, domain.c_str()+fdot+1, remain);
    domain.assign(tmp, remain); // don't dare to do this w/o tmp holder :-)
  }
  return true;
}

/** Chops off the start of a domain, so goes from 'www.ds9a.nl.' to 'ds9a.nl.' to 'nl.' to '.' Return zero on the empty string */
bool chopOffDotted(string &domain)
{
  if(domain.empty() || (domain.size()==1 && domain[0]=='.'))
    return false;

  string::size_type fdot=domain.find('.');
  if(fdot == string::npos)
    return false;

  if(fdot==domain.size()-1) 
    domain=".";
  else  {
    string::size_type remain = domain.length() - (fdot + 1);
    char tmp[remain];
    memcpy(tmp, domain.c_str()+fdot+1, remain);
    domain.assign(tmp, remain);
  }
  return true;
}


bool ciEqual(const string& a, const string& b)
{
  if(a.size()!=b.size())
    return false;

  string::size_type pos=0, epos=a.size();
  for(;pos < epos; ++pos)
    if(dns_tolower(a[pos])!=dns_tolower(b[pos]))
      return false;
  return true;
}

/** does domain end on suffix? Is smart about "wwwds9a.nl" "ds9a.nl" not matching */
bool endsOn(const string &domain, const string &suffix) 
{
  if( suffix.empty() || ciEqual(domain, suffix) )
    return true;

  if(domain.size()<=suffix.size())
    return false;
  
  string::size_type dpos=domain.size()-suffix.size()-1, spos=0;

  if(domain[dpos++]!='.')
    return false;

  for(; dpos < domain.size(); ++dpos, ++spos)
    if(dns_tolower(domain[dpos]) != dns_tolower(suffix[spos]))
      return false;

  return true;
}

/** does domain end on suffix? Is smart about "wwwds9a.nl" "ds9a.nl" not matching */
bool dottedEndsOn(const string &domain, const string &suffix) 
{
  if( suffix=="." || ciEqual(domain, suffix) )
    return true;

  if(domain.size()<=suffix.size())
    return false;
  
  string::size_type dpos=domain.size()-suffix.size()-1, spos=0;

  if(domain[dpos++]!='.')
    return false;

  for(; dpos < domain.size(); ++dpos, ++spos)
    if(dns_tolower(domain[dpos]) != dns_tolower(suffix[spos]))
      return false;

  return true;
}

int sendData(const char *buffer, int replen, int outsock)
{
  uint16_t nlen=htons(replen);
  Utility::iovec iov[2];
  iov[0].iov_base=(char*)&nlen;
  iov[0].iov_len=2;
  iov[1].iov_base=(char*)buffer;
  iov[1].iov_len=replen;
  int ret=Utility::writev(outsock,iov,2);

  if(ret <= 0)  // "EOF is error" - we can't deal with EAGAIN errors at this stage yet
    return -1;

  if(ret!=replen+2) {
    // we can safely assume ret > 2, as 2 is < PIPE_BUF
    
    buffer += (ret - 2);
    replen -= (ret - 2);

    while (replen) {
      ret = write(outsock, buffer, replen);
      if(ret < 0) {
        if(errno==EAGAIN) { // wait, we might've exhausted the window
          while(waitForRWData(outsock, false, 1, 0)==0)
            ;
          continue;
        }
        return ret;
      }
      if(!ret)
        return -1; // "EOF == error"
      replen -= ret;
      buffer += ret;
    }
    if(!replen)
      return 0;
    return -1;
  }
  return 0;
}

static void parseService4(const string &descr, ServiceTuple &st)
{
  vector<string>parts;
  stringtok(parts,descr,":");
  if(parts.empty())
    throw AhuException("Unable to parse '"+descr+"' as a service");
  st.host=parts[0];
  if(parts.size()>1)
    st.port=atoi(parts[1].c_str());
}

static void parseService6(const string &descr, ServiceTuple &st)
{
  string::size_type pos=descr.find(']');
  if(pos == string::npos)
    throw AhuException("Unable to parse '"+descr+"' as an IPv6 service");

  st.host=descr.substr(1, pos-1);
  if(pos + 2 < descr.length())
    st.port=atoi(descr.c_str() + pos +2);
}


void parseService(const string &descr, ServiceTuple &st)
{
  if(descr.empty())
    throw AhuException("Unable to parse '"+descr+"' as a service");

  vector<string> parts;
  stringtok(parts, descr, ":");

  if(descr[0]=='[') {
    parseService6(descr, st);
  }
  else if(descr[0]==':' || parts.size() > 2 || descr.find("::") != string::npos) {
    st.host=descr;
  }
  else {
    parseService4(descr, st);
  }
}

// returns -1 in case if error, 0 if no data is available, 1 if there is. In the first two cases, errno is set
int waitForData(int fd, int seconds, int useconds)
{
  return waitForRWData(fd, true, seconds, useconds);
}

int waitForRWData(int fd, bool waitForRead, int seconds, int useconds)
{
  int ret;

  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = fd;
  
  if(waitForRead)
    pfd.events=POLLIN;
  else
    pfd.events=POLLOUT;

  ret = poll(&pfd, 1, seconds * 1000 + useconds/1000);
  if ( ret == -1 )
    errno = ETIMEDOUT;

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

string uitoa(unsigned int i) // MSVC 6 doesn't grok overloading (un)signed
{
  ostringstream o;
  o<<i;
  return o.str();
}


string stringerror()
{
  return strerror(errno);
}

#ifdef WIN32
string netstringerror()
{
  char buf[512];
  int err=WSAGetLastError();
  if(FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
        	     0, buf, sizeof(buf)-1, NULL)) {
    return string(buf);
  }
  else {
    return strerror(err);
  }
}
#else
string netstringerror()
{
  return stringerror();
}
#endif

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


bool IpToU32(const string &str, uint32_t *ip)
{
  if(str.empty()) {
    *ip=0;
    return true;
  }
  
  struct in_addr inp;
  if(Utility::inet_aton(str.c_str(), &inp)) {
    *ip=inp.s_addr;
    return true;
  }
  return false;
}

string U32ToIP(uint32_t val)
{
  char tmp[17];
  snprintf(tmp, sizeof(tmp)-1, "%u.%u.%u.%u", 
           (val >> 24)&0xff,
           (val >> 16)&0xff,
           (val >>  8)&0xff,
           (val      )&0xff);
  return tmp;
}


const string sockAddrToString(struct sockaddr_in *remote) 
{    
  if(remote->sin_family == AF_INET) {
    struct sockaddr_in sip;
    memcpy(&sip,(struct sockaddr_in*)remote,sizeof(sip));
    return inet_ntoa(sip.sin_addr);
  }
  else {
    char tmp[128];
    
    if(!Utility::inet_ntop(AF_INET6, ( const char * ) &((struct sockaddr_in6 *)remote)->sin6_addr, tmp, sizeof(tmp)))
      return "IPv6 untranslateable";

    return tmp;
  }
}

string makeHexDump(const string& str)
{
  char tmp[5];
  string ret;
  ret.reserve((int)(str.size()*2.2));

  for(string::size_type n=0;n<str.size();++n) {
    sprintf(tmp,"%02x ", (unsigned char)str[n]);
    ret+=tmp;
  }
  return ret;
}



// shuffle, maintaining some semblance of order
void shuffle(vector<DNSResourceRecord>& rrs)
{
  vector<DNSResourceRecord>::iterator first, second;
  for(first=rrs.begin();first!=rrs.end();++first) 
    if(first->d_place==DNSResourceRecord::ANSWER && first->qtype.getCode() != QType::CNAME) // CNAME must come first
      break;
  for(second=first;second!=rrs.end();++second)
    if(second->d_place!=DNSResourceRecord::ANSWER)
      break;
  
  if(second-first>1)
    random_shuffle(first,second);
  
  // now shuffle the additional records
  for(first=second;first!=rrs.end();++first) 
    if(first->d_place==DNSResourceRecord::ADDITIONAL && first->qtype.getCode() != QType::CNAME) // CNAME must come first
      break;
  for(second=first;second!=rrs.end();++second)
    if(second->d_place!=DNSResourceRecord::ADDITIONAL)
      break;
  
  if(second-first>1)
    random_shuffle(first,second);

  // we don't shuffle the rest
}


void normalizeTV(struct timeval& tv)
{
  if(tv.tv_usec > 1000000) {
    ++tv.tv_sec;
    tv.tv_usec-=1000000;
  }
  else if(tv.tv_usec < 0) {
    --tv.tv_sec;
    tv.tv_usec+=1000000;
  }
}

const struct timeval operator+(const struct timeval& lhs, const struct timeval& rhs)
{
  struct timeval ret;
  ret.tv_sec=lhs.tv_sec + rhs.tv_sec;
  ret.tv_usec=lhs.tv_usec + rhs.tv_usec;
  normalizeTV(ret);
  return ret;
}

const struct timeval operator-(const struct timeval& lhs, const struct timeval& rhs)
{
  struct timeval ret;
  ret.tv_sec=lhs.tv_sec - rhs.tv_sec;
  ret.tv_usec=lhs.tv_usec - rhs.tv_usec;
  normalizeTV(ret);
  return ret;
}

pair<string, string> splitField(const string& inp, char sepa)
{
  pair<string, string> ret;
  string::size_type cpos=inp.find(sepa);
  if(cpos==string::npos)
    ret.first=inp;
  else {
    ret.first=inp.substr(0, cpos);
    ret.second=inp.substr(cpos+1);
  }
  return ret;
}

boost::optional<int> logFacilityToLOG(unsigned int facility)
{
  boost::optional<int> ret;

  switch(facility) {
  case 0:
    return LOG_LOCAL0;
  case 1:
    return(LOG_LOCAL1);
  case 2:
    return(LOG_LOCAL2);
  case 3:
    return(LOG_LOCAL3);
  case 4:
    return(LOG_LOCAL4);
  case 5:
    return(LOG_LOCAL5);
  case 6:
    return(LOG_LOCAL6);
  case 7:
    return(LOG_LOCAL7);
  default:
    return ret;
  }
}

string stripDot(const string& dom)
{
  if(dom.empty())
    return dom;

  if(dom[dom.size()-1]!='.')
    return dom;

  return dom.substr(0,dom.size()-1);
}


string labelReverse(const std::string& qname)
{
  if(qname.empty())
    return qname;

  vector<string> labels;
  stringtok(labels, qname, ".");
  if(labels.size()==1)
    return qname;

  string ret;
  for(vector<string>::const_reverse_iterator iter = labels.rbegin(); iter != labels.rend(); ++iter) {
    if(iter != labels.rbegin())
      ret.append(1,'.');
    ret+=*iter;
  }
  return ret;
}

// do NOT feed trailing dots!
// www.powerdns.com, powerdns.com -> www
string makeRelative(const std::string& fqdn, const std::string& zone)
{
  if(zone.empty())
    return fqdn;  
  if(fqdn != zone)
    return fqdn.substr(0, fqdn.size() - zone.length() - 1); // strip domain name
  return "";
}
