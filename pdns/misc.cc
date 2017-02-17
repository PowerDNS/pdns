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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/param.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>
#include <fstream>
#include "misc.hh"
#include <vector>
#include <sstream>
#include <errno.h>
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <dirent.h>
#include <algorithm>
#include <boost/optional.hpp>
#include <poll.h>
#include <iomanip>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pdnsexception.hh"
#include <sys/types.h>
#include <boost/algorithm/string.hpp>
#include "iputils.hh"
#include "dnsparser.hh"
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>


bool g_singleThreaded;

size_t writen2(int fd, const void *buf, size_t count)
{
  const char *ptr = (char*)buf;
  const char *eptr = ptr + count;

  ssize_t res;
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

    ptr += (size_t) res;
  }

  return count;
}

size_t readn2(int fd, void* buffer, size_t len)
{
  size_t pos=0;
  ssize_t res;
  for(;;) {
    res = read(fd, (char*)buffer + pos, len - pos);
    if(res == 0)
      throw runtime_error("EOF while reading message");
    if(res < 0) {
      if (errno == EAGAIN)
        throw std::runtime_error("used readn2 on non-blocking socket, got EAGAIN");
      else
        unixDie("failed in readn2");
    }

    pos+=(size_t)res;
    if(pos == len)
      break;
  }
  return len;
}

size_t readn2WithTimeout(int fd, void* buffer, size_t len, int idleTimeout, int totalTimeout)
{
  size_t pos = 0;
  time_t start = 0;
  int remainingTime = totalTimeout;
  if (totalTimeout) {
    start = time(NULL);
  }

  do {
    ssize_t got = read(fd, (char *)buffer + pos, len - pos);
    if (got > 0) {
      pos += (size_t) got;
    }
    else if (got == 0) {
      throw runtime_error("EOF while reading message");
    }
    else {
      if (errno == EAGAIN) {
        int res = waitForData(fd, (totalTimeout == 0 || idleTimeout <= remainingTime) ? idleTimeout : remainingTime);
        if (res > 0) {
          /* there is data available */
        }
        else if (res == 0) {
          throw runtime_error("Timeout while waiting for data to read");
        } else {
          throw runtime_error("Error while waiting for data to read");
        }
      }
      else {
        unixDie("failed in readn2WithTimeout");
      }
    }

    if (totalTimeout) {
      time_t now = time(NULL);
      int elapsed = now - start;
      if (elapsed >= remainingTime) {
        throw runtime_error("Timeout while reading data");
      }
      start = now;
      remainingTime -= elapsed;
    }
  }
  while (pos < len);

  return len;
}

size_t writen2WithTimeout(int fd, const void * buffer, size_t len, int timeout)
{
  size_t pos = 0;
  do {
    ssize_t written = write(fd, (char *)buffer + pos, len - pos);

    if (written > 0) {
      pos += (size_t) written;
    }
    else if (written == 0)
      throw runtime_error("EOF while writing message");
    else {
      if (errno == EAGAIN) {
        int res = waitForRWData(fd, false, timeout, 0);
        if (res > 0) {
          /* there is room available */
        }
        else if (res == 0) {
          throw runtime_error("Timeout while waiting to write data");
        } else {
          throw runtime_error("Error while waiting for room to write data");
        }
      }
      else {
        unixDie("failed in write2WithTimeout");
      }
    }
  }
  while (pos < len);

  return len;
}

string nowTime()
{
  time_t now = time(nullptr);
  struct tm* tm = localtime(&now);
  char buffer[30];
  // YYYY-mm-dd HH:MM:SS TZOFF
  strftime(buffer, sizeof(buffer), "%F %T %z", tm);
  buffer[sizeof(buffer)-1] = '\0';
  return buffer;
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

static bool ciEqual(const string& a, const string& b)
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
static bool endsOn(const string &domain, const string &suffix)
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

static void parseService4(const string &descr, ServiceTuple &st)
{
  vector<string>parts;
  stringtok(parts,descr,":");
  if(parts.empty())
    throw PDNSException("Unable to parse '"+descr+"' as a service");
  st.host=parts[0];
  if(parts.size()>1)
    st.port=pdns_stou(parts[1]);
}

static void parseService6(const string &descr, ServiceTuple &st)
{
  string::size_type pos=descr.find(']');
  if(pos == string::npos)
    throw PDNSException("Unable to parse '"+descr+"' as an IPv6 service");

  st.host=descr.substr(1, pos-1);
  if(pos + 2 < descr.length())
    st.port=pdns_stou(descr.substr(pos+2));
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

int waitForRWData(int fd, bool waitForRead, int seconds, int useconds, bool* error, bool* disconnected)
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
  if ( ret == -1 ) {
    errno = ETIMEDOUT; // ???
  }
  else if (ret > 0) {
    if (error && (pfd.revents & POLLERR)) {
      *error = true;
    }
    if (disconnected && (pfd.revents & POLLHUP)) {
      *disconnected = true;
    }
  }

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
  d_set.tv_sec=d_set.tv_usec=0;
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
  if(inet_aton(str.c_str(), &inp)) {
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
void shuffle(vector<DNSZoneRecord>& rrs)
{
  vector<DNSZoneRecord>::iterator first, second;
  for(first=rrs.begin();first!=rrs.end();++first)
    if(first->dr.d_place==DNSResourceRecord::ANSWER && first->dr.d_type != QType::CNAME) // CNAME must come first
      break;
  for(second=first;second!=rrs.end();++second)
    if(second->dr.d_place!=DNSResourceRecord::ANSWER)
      break;

  if(second-first > 1)
    random_shuffle(first,second);

  // now shuffle the additional records
  for(first=second;first!=rrs.end();++first)
    if(first->dr.d_place==DNSResourceRecord::ADDITIONAL && first->dr.d_type != QType::CNAME) // CNAME must come first
      break;
  for(second=first;second!=rrs.end();++second)
    if(second->dr.d_place!=DNSResourceRecord::ADDITIONAL)
      break;

  if(second-first>1)
    random_shuffle(first,second);

  // we don't shuffle the rest
}


// shuffle, maintaining some semblance of order
void shuffle(vector<DNSRecord>& rrs)
{
  vector<DNSRecord>::iterator first, second;
  for(first=rrs.begin();first!=rrs.end();++first)
    if(first->d_place==DNSResourceRecord::ANSWER && first->d_type != QType::CNAME) // CNAME must come first
      break;
  for(second=first;second!=rrs.end();++second)
    if(second->d_place!=DNSResourceRecord::ANSWER || second->d_type == QType::RRSIG) // leave RRSIGs at the end
      break;

  if(second-first>1)
    random_shuffle(first,second);

  // now shuffle the additional records
  for(first=second;first!=rrs.end();++first)
    if(first->d_place==DNSResourceRecord::ADDITIONAL && first->d_type != QType::CNAME) // CNAME must come first
      break;
  for(second=first; second!=rrs.end(); ++second)
    if(second->d_place!=DNSResourceRecord::ADDITIONAL)
      break;

  if(second-first>1)
    random_shuffle(first,second);

  // we don't shuffle the rest
}

static uint16_t mapTypesToOrder(uint16_t type)
{
  if(type == QType::CNAME)
    return 0;
  if(type == QType::RRSIG)
    return 65535;
  else
    return 1;
}

// make sure rrs is sorted in d_place order to avoid surprises later
// then shuffle the parts that desire shuffling
void orderAndShuffle(vector<DNSRecord>& rrs)
{
  std::stable_sort(rrs.begin(), rrs.end(), [](const DNSRecord&a, const DNSRecord& b) { 
      return std::make_tuple(a.d_place, mapTypesToOrder(a.d_type)) < std::make_tuple(b.d_place, mapTypesToOrder(b.d_type));
    });
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



int makeIPv6sockaddr(const std::string& addr, struct sockaddr_in6* ret)
{
  if(addr.empty())
    return -1;
  string ourAddr(addr);
  bool portSet = false;
  unsigned int port;
  if(addr[0]=='[') { // [::]:53 style address
    string::size_type pos = addr.find(']');
    if(pos == string::npos || pos + 2 > addr.size() || addr[pos+1]!=':')
      return -1;
    ourAddr.assign(addr.c_str() + 1, pos-1);
    try {
      port = pdns_stou(addr.substr(pos+2));
      portSet = true;
    }
    catch(std::out_of_range) {
      return -1;
    }
  }
  ret->sin6_scope_id=0;
  ret->sin6_family=AF_INET6;

  if(inet_pton(AF_INET6, ourAddr.c_str(), (void*)&ret->sin6_addr) != 1) {
    struct addrinfo* res;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_NUMERICHOST;

    int error;
    // getaddrinfo has anomalous return codes, anything nonzero is an error, positive or negative
    if((error=getaddrinfo(ourAddr.c_str(), 0, &hints, &res))) {
      return -1;
    }

    memcpy(ret, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
  }

  if(portSet) {
    if(port > 65535)
      return -1;

    ret->sin6_port = htons(port);
  }

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
    if(inet_aton(str.c_str(), &inp)) {
      ret->sin_addr.s_addr=inp.s_addr;
      return 0;
    }
    return -1;
  }
  if(!*(str.c_str() + pos + 1)) // trailing :
    return -1;

  char *eptr = (char*)str.c_str() + str.size();
  int port = strtol(str.c_str() + pos + 1, &eptr, 10);
  if (port < 0 || port > 65535)
    return -1;

  if(*eptr)
    return -1;

  ret->sin_port = htons(port);
  if(inet_aton(str.substr(0, pos).c_str(), &inp)) {
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

// if you end up here because valgrind told you were are doing something wrong
// with msgh->msg_controllen, please refer to https://github.com/PowerDNS/pdns/pull/3962
// first.
void addCMsgSrcAddr(struct msghdr* msgh, void* cmsgbuf, const ComboAddress* source, int itfIndex)
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
    pkt->ipi6_ifindex = itfIndex;
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
    pkt->ipi_ifindex = itfIndex;
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

uint32_t burtleCI(const unsigned char* k, uint32_t length, uint32_t initval)
{
  uint32_t a,b,c,len;

   /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
  c = initval;         /* the previous hash value */

  /*---------------------------------------- handle most of the key */
  while (len >= 12) {
    a += (dns_tolower(k[0]) +((uint32_t)dns_tolower(k[1])<<8) +((uint32_t)dns_tolower(k[2])<<16) +((uint32_t)dns_tolower(k[3])<<24));
    b += (dns_tolower(k[4]) +((uint32_t)dns_tolower(k[5])<<8) +((uint32_t)dns_tolower(k[6])<<16) +((uint32_t)dns_tolower(k[7])<<24));
    c += (dns_tolower(k[8]) +((uint32_t)dns_tolower(k[9])<<8) +((uint32_t)dns_tolower(k[10])<<16)+((uint32_t)dns_tolower(k[11])<<24));
    burtlemix(a,b,c);
    k += 12; len -= 12;
  }

  /*------------------------------------- handle the last 11 bytes */
  c += length;
  switch(len) {             /* all the case statements fall through */
  case 11: c+=((uint32_t)dns_tolower(k[10])<<24);
  case 10: c+=((uint32_t)dns_tolower(k[9])<<16);
  case 9 : c+=((uint32_t)dns_tolower(k[8])<<8);
    /* the first byte of c is reserved for the length */
  case 8 : b+=((uint32_t)dns_tolower(k[7])<<24);
  case 7 : b+=((uint32_t)dns_tolower(k[6])<<16);
  case 6 : b+=((uint32_t)dns_tolower(k[5])<<8);
  case 5 : b+=dns_tolower(k[4]);
  case 4 : a+=((uint32_t)dns_tolower(k[3])<<24);
  case 3 : a+=((uint32_t)dns_tolower(k[2])<<16);
  case 2 : a+=((uint32_t)dns_tolower(k[1])<<8);
  case 1 : a+=dns_tolower(k[0]);
    /* case 0: nothing left to add */
  }
  burtlemix(a,b,c);
  /*-------------------------------------------- report the result */
  return c;
}


bool setSocketTimestamps(int fd)
{
#ifdef SO_TIMESTAMP
  int on=1;
  return setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, (char*)&on, sizeof(on)) == 0;
#endif
  return true; // we pretend this happened.
}

bool setTCPNoDelay(int sock)
{
  int flag = 1;
  return setsockopt(sock,            /* socket affected */
                    IPPROTO_TCP,     /* set option at TCP level */
                    TCP_NODELAY,     /* name of option */
                    (char *) &flag,  /* the cast is historical cruft */
                    sizeof(flag)) == 0;    /* length of option value */
}


bool setNonBlocking(int sock)
{
  int flags=fcntl(sock,F_GETFL,0);
  if(flags<0 || fcntl(sock, F_SETFL,flags|O_NONBLOCK) <0)
    return false;
  return true;
}

bool setBlocking(int sock)
{
  int flags=fcntl(sock,F_GETFL,0);
  if(flags<0 || fcntl(sock, F_SETFL,flags&(~O_NONBLOCK)) <0)
    return false;
  return true;
}

bool isNonBlocking(int sock)
{
  int flags=fcntl(sock,F_GETFL,0);
  return flags & O_NONBLOCK;
}

// Closes a socket.
int closesocket( int socket )
{
  int ret=::close(socket);
  if(ret < 0 && errno == ECONNRESET) // see ticket 192, odd BSD behaviour
    return 0;
  if(ret < 0)
    throw PDNSException("Error closing socket: "+stringerror());
  return ret;
}

bool setCloseOnExec(int sock)
{
  int flags=fcntl(sock,F_GETFD,0);
  if(flags<0 || fcntl(sock, F_SETFD,flags|FD_CLOEXEC) <0)
    return false;
  return true;
}

string getMACAddress(const ComboAddress& ca)
{
  string ret;
#ifdef __linux__
  ifstream ifs("/proc/net/arp");
  if(!ifs)
    return ret;
  string line;
  string match=ca.toString()+' ';
  while(getline(ifs, line)) {
    if(boost::starts_with(line, match)) {
      vector<string> parts;
      stringtok(parts, line, " \n\t\r");
      if(parts.size() < 4)
        return ret;
      unsigned int tmp[6];
      sscanf(parts[3].c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", tmp, tmp+1, tmp+2, tmp+3, tmp+4, tmp+5);
      for(int i = 0 ; i< 6 ; ++i)
        ret.append(1, (char)tmp[i]);
      return ret;
    }
  }
#endif
  return ret;
}

uint64_t udpErrorStats(const std::string& str)
{
#ifdef __linux__
  ifstream ifs("/proc/net/snmp");
  if(!ifs)
    return 0;
  string line;
  vector<string> parts;
  while(getline(ifs,line)) {
    if(boost::starts_with(line, "Udp: ") && isdigit(line[5])) {
      stringtok(parts, line, " \n\t\r");
      if(parts.size() < 7)
	break;
      if(str=="udp-rcvbuf-errors")
	return std::stoull(parts[5]);
      else if(str=="udp-sndbuf-errors")
	return std::stoull(parts[6]);
      else if(str=="udp-noport-errors")
	return std::stoull(parts[2]);
      else if(str=="udp-in-errors")
	return std::stoull(parts[3]);
      else
	return 0;
    }
  }
#endif
  return 0;
}

bool getTSIGHashEnum(const DNSName& algoName, TSIGHashEnum& algoEnum)
{
  if (algoName == DNSName("hmac-md5.sig-alg.reg.int") || algoName == DNSName("hmac-md5"))
    algoEnum = TSIG_MD5;
  else if (algoName == DNSName("hmac-sha1"))
    algoEnum = TSIG_SHA1;
  else if (algoName == DNSName("hmac-sha224"))
    algoEnum = TSIG_SHA224;
  else if (algoName == DNSName("hmac-sha256"))
    algoEnum = TSIG_SHA256;
  else if (algoName == DNSName("hmac-sha384"))
    algoEnum = TSIG_SHA384;
  else if (algoName == DNSName("hmac-sha512"))
    algoEnum = TSIG_SHA512;
  else if (algoName == DNSName("gss-tsig"))
    algoEnum = TSIG_GSS;
  else {
     return false;
  }
  return true;
}

DNSName getTSIGAlgoName(TSIGHashEnum& algoEnum)
{
  switch(algoEnum) {
  case TSIG_MD5: return DNSName("hmac-md5.sig-alg.reg.int.");
  case TSIG_SHA1: return DNSName("hmac-sha1.");
  case TSIG_SHA224: return DNSName("hmac-sha224.");
  case TSIG_SHA256: return DNSName("hmac-sha256.");
  case TSIG_SHA384: return DNSName("hmac-sha384.");
  case TSIG_SHA512: return DNSName("hmac-sha512.");
  case TSIG_GSS: return DNSName("gss-tsig.");
  }
  throw PDNSException("getTSIGAlgoName does not understand given algorithm, please fix!");
}

uint64_t getOpenFileDescriptors(const std::string&)
{
#ifdef __linux__
  DIR* dirhdl=opendir(("/proc/"+std::to_string(getpid())+"/fd/").c_str());
  if(!dirhdl) 
    return 0;

  struct dirent *entry;
  int ret=0;
  while((entry = readdir(dirhdl))) {
    uint32_t num;
    try {
      num = pdns_stou(entry->d_name);
    } catch (...) {
      continue; // was not a number.
    }
    if(std::to_string(num) == entry->d_name)
      ret++;
  }
  closedir(dirhdl);
  return ret;

#else
  return 0;
#endif
}

uint64_t getRealMemoryUsage(const std::string&)
{
#ifdef __linux__
  ifstream ifs("/proc/"+std::to_string(getpid())+"/smaps");
  if(!ifs)
    return 0;
  string line;
  uint64_t bytes=0;
  string header("Private_Dirty:");
  while(getline(ifs, line)) {
    if(boost::starts_with(line, header)) {
      bytes += std::stoull(line.substr(header.length() + 1))*1024;
    }
  }
  return bytes;
#else
  return 0;
#endif
}

uint64_t getCPUTimeUser(const std::string&)
{
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  return (ru.ru_utime.tv_sec*1000ULL + ru.ru_utime.tv_usec/1000);
}

uint64_t getCPUTimeSystem(const std::string&)
{
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  return (ru.ru_stime.tv_sec*1000ULL + ru.ru_stime.tv_usec/1000);
}

double DiffTime(const struct timespec& first, const struct timespec& second)
{
  int seconds=second.tv_sec - first.tv_sec;
  int nseconds=second.tv_nsec - first.tv_nsec;
  
  if(nseconds < 0) {
    seconds-=1;
    nseconds+=1000000000;
  }
  return seconds + nseconds/1000000000.0;
}

double DiffTime(const struct timeval& first, const struct timeval& second)
{
  int seconds=second.tv_sec - first.tv_sec;
  int useconds=second.tv_usec - first.tv_usec;
  
  if(useconds < 0) {
    seconds-=1;
    useconds+=1000000;
  }
  return seconds + useconds/1000000.0;
}

uid_t strToUID(const string &str)
{
  uid_t result = 0;
  const char * cstr = str.c_str();
  struct passwd * pwd = getpwnam(cstr);

  if (pwd == NULL) {
    long long val;

    try {
      val = stoll(str);
    }
    catch(std::exception& e) {
      throw runtime_error((boost::format("Error: Unable to parse user ID %s") % cstr).str() );
    }

    if (val < std::numeric_limits<uid_t>::min() || val > std::numeric_limits<uid_t>::max()) {
      throw runtime_error((boost::format("Error: Unable to parse user ID %s") % cstr).str() );
    }

    result = static_cast<uid_t>(val);
  }
  else {
    result = pwd->pw_uid;
  }

  return result;
}

gid_t strToGID(const string &str)
{
  gid_t result = 0;
  const char * cstr = str.c_str();
  struct group * grp = getgrnam(cstr);

  if (grp == NULL) {
    long long val;

    try {
      val = stoll(str);
    }
    catch(std::exception& e) {
      throw runtime_error((boost::format("Error: Unable to parse group ID %s") % cstr).str() );
    }

    if (val < std::numeric_limits<gid_t>::min() || val > std::numeric_limits<gid_t>::max()) {
      throw runtime_error((boost::format("Error: Unable to parse group ID %s") % cstr).str() );
    }

    result = static_cast<gid_t>(val);
  }
  else {
    result = grp->gr_gid;
  }

  return result;
}

unsigned int pdns_stou(const std::string& str, size_t * idx, int base)
{
  if (str.empty()) return 0; // compatibility
  unsigned long result = std::stoul(str, idx, base);
  if (result > std::numeric_limits<unsigned int>::max()) {
    throw std::out_of_range("stou");
  }
  return static_cast<unsigned int>(result);
}

