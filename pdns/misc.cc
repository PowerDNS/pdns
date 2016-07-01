/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <sys/param.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>
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
#include "pdnsexception.hh"
#include <sys/types.h>
#include "utility.hh"
#include <boost/algorithm/string.hpp>
#include "logger.hh"
#include "iputils.hh"

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

int readn2(int fd, void* buffer, unsigned int len)
{
  unsigned int pos=0;
  int res;
  for(;;) {
    res = read(fd, (char*)buffer + pos, len - pos);
    if(res == 0) 
      throw runtime_error("EOF while writing message");
    if(res < 0) {
      if (errno == EAGAIN)
        throw std::runtime_error("used writen2 on non-blocking socket, got EAGAIN");
      else
        unixDie("failed in writen2");
    } 
    
    pos+=res;
    if(pos == len)
      break;
  }
  return len;
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

  bool escaped = false;
  const string::size_type domainLen = domain.length();
  for (size_t fdot = 0; fdot < domainLen; fdot++)
  {
    if (domain[fdot] == '.' && !escaped) {
      string::size_type remain = domainLen - (fdot + 1);
      char tmp[remain];
      memcpy(tmp, domain.c_str()+fdot+1, remain);
      domain.assign(tmp, remain); // don't dare to do this w/o tmp holder :-)

      return true;
    }
    else if (domain[fdot] == '\\' && !escaped) {
      escaped = true;
    }
    else {
      escaped = false;
    }
  }

  domain = "";
  return true;
}

/** Chops off the start of a domain, so goes from 'www.ds9a.nl.' to 'ds9a.nl.' to 'nl.' to '.' Return zero on the empty string */
bool chopOffDotted(string &domain)
{
  if(domain.empty() || (domain.size()==1 && domain[0]=='.'))
    return false;

  bool escaped = false;
  const string::size_type domainLen = domain.length();
  for (size_t fdot = 0; fdot < domainLen; fdot++)
  {
    if (domain[fdot] == '.' && !escaped) {
      if (fdot==domain.size()-1) {
        domain=".";
      }
      else {
        string::size_type remain = domainLen - (fdot + 1);
        char tmp[remain];
        memcpy(tmp, domain.c_str()+fdot+1, remain);
        domain.assign(tmp, remain); // don't dare to do this w/o tmp holder :-)
      }
      return true;
    }
    else if (domain[fdot] == '\\' && !escaped) {
      escaped = true;
    }
    else {
      escaped = false;
    }
  }

  return false;
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

static void parseService4(const string &descr, ServiceTuple &st)
{
  vector<string>parts;
  stringtok(parts,descr,":");
  if(parts.empty())
    throw PDNSException("Unable to parse '"+descr+"' as a service");
  st.host=parts[0];
  if(parts.size()>1)
    st.port=atoi(parts[1].c_str());
}

static void parseService6(const string &descr, ServiceTuple &st)
{
  string::size_type pos=descr.find(']');
  if(pos == string::npos)
    throw PDNSException("Unable to parse '"+descr+"' as an IPv6 service");

  st.host=descr.substr(1, pos-1);
  if(pos + 2 < descr.length())
    st.port=atoi(descr.c_str() + pos +2);
}


void parseService(const string &descr, ServiceTuple &st)
{
  if(descr.empty())
    throw PDNSException("Unable to parse '"+descr+"' as a service");

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
    errno = ETIMEDOUT; // ???

  return ret;
}

// returns -1 in case of error, 0 if no data is available, 1 if there is. In the first two cases, errno is set
int waitFor2Data(int fd1, int fd2, int seconds, int useconds, int*fd)
{
  int ret;

  struct pollfd pfds[2];
  memset(&pfds[0], 0, 2*sizeof(struct pollfd));
  pfds[0].fd = fd1;
  pfds[1].fd = fd2;
  
  pfds[0].events= pfds[1].events = POLLIN;

  int nsocks = 1 + (fd2 >= 0); // fd2 can optionally be -1

  if(seconds >= 0)
    ret = poll(pfds, nsocks, seconds * 1000 + useconds/1000);
  else
    ret = poll(pfds, nsocks, -1);
  if(!ret || ret < 0)
    return ret;
    
  if((pfds[0].revents & POLLIN) && !(pfds[1].revents & POLLIN))
    *fd = pfds[0].fd;
  else if((pfds[1].revents & POLLIN) && !(pfds[0].revents & POLLIN))
    *fd = pfds[1].fd;
  else if(ret == 2) {
    *fd = pfds[random()%2].fd;
  }
  else
    *fd = -1; // should never happen
  
  return 1;
}


string humanDuration(time_t passed)
{
  ostringstream ret;
  if(passed<60)
    ret<<passed<<" seconds";
  else if(passed<3600)
    ret<<std::setprecision(2)<<passed/60.0<<" minutes";
  else if(passed<86400)
    ret<<std::setprecision(3)<<passed/3600.0<<" hours";
  else if(passed<(86400*30.41))
    ret<<std::setprecision(3)<<passed/86400.0<<" days";
  else
    ret<<std::setprecision(3)<<passed/(86400*30.41)<<" months";

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
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

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

string bitFlip(const string &str)
{
  string::size_type pos=0, epos=str.size();
  string ret;
  ret.reserve(epos);
  for(;pos < epos; ++pos)
    ret.append(1, ~str[pos]);
  return ret;
}

string stringerror()
{
  return strerror(errno);
}

string netstringerror()
{
  return stringerror();
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

static bool comparePlace(DNSResourceRecord a, DNSResourceRecord b)
{
  return (a.d_place < b.d_place);
}

// make sure rrs is sorted in d_place order to avoid surprises later
// then shuffle the parts that desire shuffling
void orderAndShuffle(vector<DNSResourceRecord>& rrs)
{
  std::stable_sort(rrs.begin(), rrs.end(), comparePlace);
  shuffle(rrs);
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

int logFacilityToLOG(unsigned int facility)
{
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
    return -1;
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

  bool dotName = qname.find('.') != string::npos;

  vector<string> labels;
  stringtok(labels, qname, ". ");
  if(labels.size()==1)
    return qname;

  string ret;  // vv const_reverse_iter http://gcc.gnu.org/bugzilla/show_bug.cgi?id=11729
  for(vector<string>::reverse_iterator iter = labels.rbegin(); iter != labels.rend(); ++iter) {
    if(iter != labels.rbegin())
      ret.append(1, dotName ? ' ' : '.');
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
  if(toLower(fqdn) != toLower(zone))
    return fqdn.substr(0, fqdn.size() - zone.length() - 1); // strip domain name
  return "";
}

string dotConcat(const std::string& a, const std::string &b)
{
  if(a.empty() || b.empty())
    return a+b;
  else 
    return a+"."+b;
}

int makeIPv6sockaddr(const std::string& addr, struct sockaddr_in6* ret)
{
  if(addr.empty())
    return -1;
  string ourAddr(addr);
  int port = -1;
  if(addr[0]=='[') { // [::]:53 style address
    string::size_type pos = addr.find(']');
    if(pos == string::npos || pos + 2 > addr.size() || addr[pos+1]!=':')
      return -1;
    ourAddr.assign(addr.c_str() + 1, pos-1);
    port = atoi(addr.c_str()+pos+2);  
  }
  
  if(inet_pton(AF_INET6, ourAddr.c_str(), (void*)&ret->sin6_addr) != 1) {
    struct addrinfo* res;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_NUMERICHOST;
    
    int error;
    if((error=getaddrinfo(ourAddr.c_str(), 0, &hints, &res))) { // this is correct
      return -1;
    }
  
    memcpy(ret, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
  }

  if(port >= 0)
    ret->sin6_port = htons(port);

  return 0;
}

int makeIPv4sockaddr(const std::string& str, struct sockaddr_in* ret)
{
  if(str.empty()) {
    return -1;
  }
  struct in_addr inp;
  
  string::size_type pos = str.find(':');
  if(pos == string::npos) { // no port specified, not touching the port
    if(Utility::inet_aton(str.c_str(), &inp)) {
      ret->sin_addr.s_addr=inp.s_addr;
      return 0;
    }
    return -1;
  }
  if(!*(str.c_str() + pos + 1)) // trailing :
    return -1; 
    
  char *eptr = (char*)str.c_str() + str.size();
  int port = strtol(str.c_str() + pos + 1, &eptr, 10);
  if(*eptr)
    return -1;
  
  ret->sin_port = htons(port);
  if(Utility::inet_aton(str.substr(0, pos).c_str(), &inp)) {
    ret->sin_addr.s_addr=inp.s_addr;
    return 0;
  }
  return -1;
}

int makeUNsockaddr(const std::string& path, struct sockaddr_un* ret)
{
  if (path.empty())
    return -1;

  memset(ret, 0, sizeof(struct sockaddr_un));
  ret->sun_family = AF_UNIX;
  if (path.length() >= sizeof(ret->sun_path))
    return -1;

  path.copy(ret->sun_path, sizeof(ret->sun_path), 0);
  return 0;
}

//! read a line of text from a FILE* to a std::string, returns false on 'no data'
bool stringfgets(FILE* fp, std::string& line)
{
  char buffer[1024];
  line.clear();
  
  do {
    if(!fgets(buffer, sizeof(buffer), fp))
      return !line.empty();
    
    line.append(buffer); 
  } while(!strchr(buffer, '\n'));
  return true;
}

bool readFileIfThere(const char* fname, std::string* line)
{
  line->clear();
  FILE* fp = fopen(fname, "r");
  if(!fp)
    return false;
  stringfgets(fp, *line);
  fclose(fp);
  return true;
}

Regex::Regex(const string &expr)
{
  if(regcomp(&d_preg, expr.c_str(), REG_ICASE|REG_NOSUB|REG_EXTENDED))
    throw PDNSException("Regular expression did not compile");
}

void addCMsgSrcAddr(struct msghdr* msgh, void* cmsgbuf, ComboAddress* source)
{
  struct cmsghdr *cmsg = NULL;

  if(source->sin4.sin_family == AF_INET6) {
    struct in6_pktinfo *pkt;

    msgh->msg_control = cmsgbuf;
    msgh->msg_controllen = CMSG_SPACE(sizeof(*pkt));

    cmsg = CMSG_FIRSTHDR(msgh);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

    pkt = (struct in6_pktinfo *) CMSG_DATA(cmsg);
    memset(pkt, 0, sizeof(*pkt));
    pkt->ipi6_addr = source->sin6.sin6_addr;
    msgh->msg_controllen = cmsg->cmsg_len; // makes valgrind happy and is slightly better style
  }
  else {
#ifdef IP_PKTINFO
    struct in_pktinfo *pkt;

    msgh->msg_control = cmsgbuf;
    msgh->msg_controllen = CMSG_SPACE(sizeof(*pkt));

    cmsg = CMSG_FIRSTHDR(msgh);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

    pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
    memset(pkt, 0, sizeof(*pkt));
    pkt->ipi_spec_dst = source->sin4.sin_addr;
    msgh->msg_controllen = cmsg->cmsg_len;
#endif
#ifdef IP_SENDSRCADDR
    struct in_addr *in;

    msgh->msg_control = cmsgbuf;
    msgh->msg_controllen = CMSG_SPACE(sizeof(*in));

    cmsg = CMSG_FIRSTHDR(msgh);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_SENDSRCADDR;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*in));

    in = (struct in_addr *) CMSG_DATA(cmsg);
    *in = source->sin4.sin_addr;
    msgh->msg_controllen = cmsg->cmsg_len;
#endif
  }
}

unsigned int getFilenumLimit(bool hardOrSoft)
{
  struct rlimit rlim;
  if(getrlimit(RLIMIT_NOFILE, &rlim) < 0)
    unixDie("Requesting number of available file descriptors");
  return hardOrSoft ? rlim.rlim_max : rlim.rlim_cur;
}

void setFilenumLimit(unsigned int lim)
{
  struct rlimit rlim;

  if(getrlimit(RLIMIT_NOFILE, &rlim) < 0)
    unixDie("Requesting number of available file descriptors");
  rlim.rlim_cur=lim;
  if(setrlimit(RLIMIT_NOFILE, &rlim) < 0)
    unixDie("Setting number of available file descriptors");
}

#define burtlemix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

uint32_t burtle(const unsigned char* k, uint32_t length, uint32_t initval)
{
  uint32_t a,b,c,len;

   /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
  c = initval;         /* the previous hash value */

  /*---------------------------------------- handle most of the key */
  while (len >= 12) {
    a += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
    b += (k[4] +((uint32_t)k[5]<<8) +((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
    c += (k[8] +((uint32_t)k[9]<<8) +((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));
    burtlemix(a,b,c);
    k += 12; len -= 12;
  }

  /*------------------------------------- handle the last 11 bytes */
  c += length;
  switch(len) {             /* all the case statements fall through */
  case 11: c+=((uint32_t)k[10]<<24);
  case 10: c+=((uint32_t)k[9]<<16);
  case 9 : c+=((uint32_t)k[8]<<8);
    /* the first byte of c is reserved for the length */
  case 8 : b+=((uint32_t)k[7]<<24);
  case 7 : b+=((uint32_t)k[6]<<16);
  case 6 : b+=((uint32_t)k[5]<<8);
  case 5 : b+=k[4];
  case 4 : a+=((uint32_t)k[3]<<24);
  case 3 : a+=((uint32_t)k[2]<<16);
  case 2 : a+=((uint32_t)k[1]<<8);
  case 1 : a+=k[0];
    /* case 0: nothing left to add */
  }
  burtlemix(a,b,c);
  /*-------------------------------------------- report the result */
  return c;
}
