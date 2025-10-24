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
#include <ctime>
#include <sys/resource.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>
#include <fstream>
#include "misc.hh"
#include <vector>
#include <string>
#include <sstream>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <dirent.h>
#include <algorithm>
#include <poll.h>
#include <iomanip>
#include <netinet/tcp.h>
#include <optional>
#include <cstdlib>
#include <cstdio>
#include "pdnsexception.hh"
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include "iputils.hh"
#include "dnsparser.hh"
#include "dns_random.hh"
#include <pwd.h>
#include <grp.h>
#include <climits>
#include <unordered_map>
#ifdef __FreeBSD__
#  include <pthread_np.h>
#endif
#ifdef __NetBSD__
#  include <pthread.h>
#  include <sched.h>
#endif

#if defined(HAVE_LIBCRYPTO)
#include <openssl/err.h>
#endif // HAVE_LIBCRYPTO

size_t writen2(int fileDesc, const void *buf, size_t count)
{
  const char *ptr = static_cast<const char*>(buf);
  const char *eptr = ptr + count;

  while (ptr != eptr) {
    auto res = ::write(fileDesc, ptr, eptr - ptr);
    if (res < 0) {
      if (errno == EAGAIN) {
        throw std::runtime_error("used writen2 on non-blocking socket, got EAGAIN");
      }
      unixDie("failed in writen2");
    }
    else if (res == 0) {
      throw std::runtime_error("could not write all bytes, got eof in writen2");
    }

    ptr += res;
  }

  return count;
}

size_t readn2(int fileDesc, void* buffer, size_t len)
{
  size_t pos = 0;

  for (;;) {
    auto res = read(fileDesc, static_cast<char *>(buffer) + pos, len - pos); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic): it's the API
    if (res == 0) {
      throw runtime_error("EOF while reading message");
    }
    if (res < 0) {
      if (errno == EAGAIN) {
        throw std::runtime_error("used readn2 on non-blocking socket, got EAGAIN");
      }
      unixDie("failed in readn2");
    }

    pos += static_cast<size_t>(res);
    if (pos == len) {
      break;
    }
  }
  return len;
}

size_t readn2WithTimeout(int fd, void* buffer, size_t len, const struct timeval& idleTimeout, const struct timeval& totalTimeout, bool allowIncomplete)
{
  size_t pos = 0;
  struct timeval start{0,0};
  struct timeval remainingTime = totalTimeout;
  if (totalTimeout.tv_sec != 0 || totalTimeout.tv_usec != 0) {
    gettimeofday(&start, nullptr);
  }

  do {
    ssize_t got = read(fd, (char *)buffer + pos, len - pos);
    if (got > 0) {
      pos += (size_t) got;
      if (allowIncomplete) {
        break;
      }
    }
    else if (got == 0) {
      throw runtime_error("EOF while reading message");
    }
    else {
      if (errno == EAGAIN) {
        struct timeval w = ((totalTimeout.tv_sec == 0 && totalTimeout.tv_usec == 0) || idleTimeout <= remainingTime) ? idleTimeout : remainingTime;
        int res = waitForData(fd, w.tv_sec, w.tv_usec);
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

    if (totalTimeout.tv_sec != 0 || totalTimeout.tv_usec != 0) {
      struct timeval now;
      gettimeofday(&now, nullptr);
      struct timeval elapsed = now - start;
      if (remainingTime < elapsed) {
        throw runtime_error("Timeout while reading data");
      }
      start = now;
      remainingTime = remainingTime - elapsed;
    }
  }
  while (pos < len);

  return len;
}

size_t writen2WithTimeout(int fd, const void * buffer, size_t len, const struct timeval& timeout)
{
  size_t pos = 0;
  do {
    ssize_t written = write(fd, reinterpret_cast<const char *>(buffer) + pos, len - pos);

    if (written > 0) {
      pos += (size_t) written;
    }
    else if (written == 0)
      throw runtime_error("EOF while writing message");
    else {
      if (errno == EAGAIN) {
        int res = waitForRWData(fd, false, timeout.tv_sec, timeout.tv_usec);
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

auto pdns::getMessageFromErrno(const int errnum) -> std::string
{
  const size_t errLen = 2048;
  std::string errMsgData{};
  errMsgData.resize(errLen);

  const char* errMsg = nullptr;
#ifdef STRERROR_R_CHAR_P
  errMsg = strerror_r(errnum, errMsgData.data(), errMsgData.length());
#else
  // This can fail, and when it does, it sets errno. We ignore that and
  // set our own error message instead.
  int res = strerror_r(errnum, errMsgData.data(), errMsgData.length());
  errMsg = errMsgData.c_str();
  if (res != 0) {
    errMsg = "Unknown (the exact error could not be retrieved)";
  }
#endif

  // We make a copy here because `strerror_r()` might return a static
  // immutable buffer for an error message. The copy shouldn't be
  // critical though, we're on the bailout/error-handling path anyways.
  std::string message{errMsg};
  return message;
}

#if defined(HAVE_LIBCRYPTO)
auto pdns::OpenSSL::error(const std::string& errorMessage) -> std::runtime_error
{
  unsigned long errorCode = 0;
  auto fullErrorMessage{errorMessage};
#if OPENSSL_VERSION_MAJOR >= 3
  const char* filename = nullptr;
  const char* functionName = nullptr;
  int lineNumber = 0;
  while ((errorCode = ERR_get_error_all(&filename, &lineNumber, &functionName, nullptr, nullptr)) != 0) {
    fullErrorMessage += std::string(": ") + std::to_string(errorCode);

    const auto* lib = ERR_lib_error_string(errorCode);
    if (lib != nullptr) {
      fullErrorMessage += std::string(":") + lib;
    }

    const auto* reason = ERR_reason_error_string(errorCode);
    if (reason != nullptr) {
      fullErrorMessage += std::string("::") + reason;
    }

    if (filename != nullptr) {
      fullErrorMessage += std::string(" - ") + filename;
    }
    if (lineNumber != 0) {
      fullErrorMessage += std::string(":") + std::to_string(lineNumber);
    }
    if (functionName != nullptr) {
      fullErrorMessage += std::string(" - ") + functionName;
    }
  }
#else
  while ((errorCode = ERR_get_error()) != 0) {
    fullErrorMessage += std::string(": ") + std::to_string(errorCode);

    const auto* lib = ERR_lib_error_string(errorCode);
    if (lib != nullptr) {
      fullErrorMessage += std::string(":") + lib;
    }

    const auto* func = ERR_func_error_string(errorCode);
    if (func != nullptr) {
      fullErrorMessage += std::string(":") + func;
    }

    const auto* reason = ERR_reason_error_string(errorCode);
    if (reason != nullptr) {
      fullErrorMessage += std::string("::") + reason;
    }
  }
#endif
  return std::runtime_error{fullErrorMessage};
}

auto pdns::OpenSSL::error(const std::string& componentName, const std::string& errorMessage) -> std::runtime_error
{
  return pdns::OpenSSL::error(componentName + ": " + errorMessage);
}
#endif // HAVE_LIBCRYPTO

string nowTime()
{
  time_t now = time(nullptr);
  struct tm theTime{};
  localtime_r(&now, &theTime);
  std::array<char, 30> buffer{};
  // YYYY-mm-dd HH:MM:SS TZOFF
  size_t ret = strftime(buffer.data(), buffer.size(), "%F %T %z", &theTime);
  if (ret == 0) {
    buffer[0] = '\0';
  }
  return {buffer.data()};
}

static bool ciEqual(const string& lhs, const string& rhs)
{
  if (lhs.size() != rhs.size()) {
    return false;
  }

  string::size_type pos = 0;
  const string::size_type epos = lhs.size();
  for (; pos < epos; ++pos) {
    if (dns_tolower(lhs[pos]) != dns_tolower(rhs[pos])) {
      return false;
    }
  }
  return true;
}

/** does domain end on suffix? Is smart about "wwwds9a.nl" "ds9a.nl" not matching */
static bool endsOn(const string &domain, const string &suffix)
{
  if( suffix.empty() || ciEqual(domain, suffix) ) {
    return true;
  }

  if(domain.size() <= suffix.size()) {
    return false;
  }

  string::size_type dpos = domain.size() - suffix.size() - 1;
  string::size_type spos = 0;

  if (domain[dpos++] != '.') {
    return false;
  }

  for(; dpos < domain.size(); ++dpos, ++spos) {
    if (dns_tolower(domain[dpos]) != dns_tolower(suffix[spos])) {
      return false;
    }
  }

  return true;
}

/** strips a domain suffix from a domain, returns true if it stripped */
bool stripDomainSuffix(string *qname, const string &domain)
{
  if (!endsOn(*qname, domain)) {
    return false;
  }

  if (toLower(*qname) == toLower(domain)) {
    *qname="@";
  }
  else {
    if ((*qname)[qname->size() - domain.size() - 1] != '.') {
      return false;
    }

    qname->resize(qname->size() - domain.size()-1);
  }
  return true;
}

// returns -1 in case if error, 0 if no data is available, 1 if there is. In the first two cases, errno is set
int waitForData(int fileDesc, int seconds, int useconds)
{
  return waitForRWData(fileDesc, true, seconds, useconds);
}

int waitForRWData(int fileDesc, bool waitForRead, int seconds, int useconds, bool* error, bool* disconnected)
{
  struct pollfd pfd{};
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = fileDesc;

  if (waitForRead) {
    pfd.events = POLLIN;
  }
  else {
    pfd.events = POLLOUT;
  }

  int ret = poll(&pfd, 1, seconds * 1000 + useconds/1000);
  if (ret > 0) {
    if ((error != nullptr) && (pfd.revents & POLLERR) != 0) {
      *error = true;
    }
    if ((disconnected != nullptr) && (pfd.revents & POLLHUP) != 0) {
      *disconnected = true;
    }
  }

  return ret;
}

// returns -1 in case of error, 0 if no data is available, 1 if there is. In the first two cases, errno is set
int waitForMultiData(const set<int>& fds, const int seconds, const int useconds, int* fdOut) {
  set<int> realFDs;
  for (const auto& fd : fds) {
    if (fd >= 0 && realFDs.count(fd) == 0) {
      realFDs.insert(fd);
    }
  }

  std::vector<struct pollfd> pfds(realFDs.size());
  memset(pfds.data(), 0, realFDs.size()*sizeof(struct pollfd));
  int ctr = 0;
  for (const auto& fd : realFDs) {
    pfds[ctr].fd = fd;
    pfds[ctr].events = POLLIN;
    ctr++;
  }

  int ret;
  if(seconds >= 0)
    ret = poll(pfds.data(), realFDs.size(), seconds * 1000 + useconds/1000);
  else
    ret = poll(pfds.data(), realFDs.size(), -1);
  if(ret <= 0)
    return ret;

  set<int> pollinFDs;
  for (const auto& pfd : pfds) {
    if (pfd.revents & POLLIN) {
      pollinFDs.insert(pfd.fd);
    }
  }
  set<int>::const_iterator it(pollinFDs.begin());
  advance(it, dns_random(pollinFDs.size()));
  *fdOut = *it;
  return 1;
}

// returns -1 in case of error, 0 if no data is available, 1 if there is. In the first two cases, errno is set
int waitFor2Data(int fd1, int fd2, int seconds, int useconds, int* fdPtr)
{
  std::array<pollfd,2> pfds{};
  memset(pfds.data(), 0, pfds.size() * sizeof(struct pollfd));
  pfds[0].fd = fd1;
  pfds[1].fd = fd2;

  pfds[0].events= pfds[1].events = POLLIN;

  int nsocks = 1 + static_cast<int>(fd2 >= 0); // fd2 can optionally be -1

  int ret{};
  if (seconds >= 0) {
    ret = poll(pfds.data(), nsocks, seconds * 1000 + useconds / 1000);
  }
  else {
    ret = poll(pfds.data(), nsocks, -1);
  }
  if (ret <= 0) {
    return ret;
  }

  if ((pfds[0].revents & POLLIN) != 0 && (pfds[1].revents & POLLIN) == 0) {
    *fdPtr = pfds[0].fd;
  }
  else if ((pfds[1].revents & POLLIN) != 0 && (pfds[0].revents & POLLIN) == 0) {
    *fdPtr = pfds[1].fd;
  }
  else if(ret == 2) {
    *fdPtr = pfds.at(dns_random_uint32() % 2).fd;
  }
  else {
    *fdPtr = -1; // should never happen
  }

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

string unquotify(const string &item)
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
  for(char i : text)
    if(i==' ')ret.append("%20");
    else ret.append(1,i);
  return ret;
}

static size_t getMaxHostNameSize()
{
#if defined(HOST_NAME_MAX)
  return HOST_NAME_MAX;
#endif

#if defined(_SC_HOST_NAME_MAX)
  auto tmp = sysconf(_SC_HOST_NAME_MAX);
  if (tmp != -1) {
    return tmp;
  }
#endif

  const size_t maxHostNameSize = 255;
  return maxHostNameSize;
}

std::optional<string> getHostname()
{
  const size_t maxHostNameBufSize = getMaxHostNameSize() + 1;
  std::string hostname;
  hostname.resize(maxHostNameBufSize, 0);

  if (gethostname(hostname.data(), maxHostNameBufSize) == -1) {
    return std::nullopt;
  }

  hostname.resize(strlen(hostname.c_str()));
  return std::make_optional(hostname);
}

std::string getCarbonHostName()
{
  auto hostname = getHostname();
  if (!hostname.has_value()) {
    throw std::runtime_error(stringerror());
  }

  std::replace(hostname->begin(), hostname->end(), '.', '_');
  return *hostname;
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

void cleanSlashes(string &str)
{
  string out;
  bool keepNextSlash = true;
  for (const auto& value : str) {
    if (value == '/') {
      if (keepNextSlash) {
        keepNextSlash = false;
      }
      else {
        continue;
      }
    }
    else {
      keepNextSlash = true;
    }
    out.append(1, value);
  }
  str = std::move(out);
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
  snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u",
           (val >> 24)&0xff,
           (val >> 16)&0xff,
           (val >>  8)&0xff,
           (val      )&0xff);
  return string(tmp);
}


string makeHexDump(const string& str, const string& sep)
{
  std::array<char, 5> tmp;
  string ret;
  ret.reserve(static_cast<size_t>(str.size() * (2 + sep.size())));

  for (char n : str) {
    snprintf(tmp.data(), tmp.size(), "%02x", static_cast<unsigned char>(n));
    ret += tmp.data();
    ret += sep;
  }
  return ret;
}

string makeBytesFromHex(const string &in) {
  if (in.size() % 2 != 0) {
    throw std::range_error("odd number of bytes in hex string");
  }
  string ret;
  ret.reserve(in.size() / 2);

  for (size_t i = 0; i < in.size(); i += 2) {
    const auto numStr = in.substr(i, 2);
    unsigned int num = 0;
    if (sscanf(numStr.c_str(), "%02x", &num) != 1) {
      throw std::range_error("Invalid value while parsing the hex string '" + in + "'");
    }
    ret.push_back(static_cast<uint8_t>(num));
  }

  return ret;
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

struct timeval operator+(const struct timeval& lhs, const struct timeval& rhs)
{
  struct timeval ret;
  ret.tv_sec=lhs.tv_sec + rhs.tv_sec;
  ret.tv_usec=lhs.tv_usec + rhs.tv_usec;
  normalizeTV(ret);
  return ret;
}

struct timeval operator-(const struct timeval& lhs, const struct timeval& rhs)
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

std::optional<int> logFacilityFromString(std::string facilityStr)
{
  static std::unordered_map<std::string, int> const s_facilities = {
    {"local0", LOG_LOCAL0},
    {"log_local0", LOG_LOCAL0},
    {"local1", LOG_LOCAL1},
    {"log_local1", LOG_LOCAL1},
    {"local2", LOG_LOCAL2},
    {"log_local2", LOG_LOCAL2},
    {"local3", LOG_LOCAL3},
    {"log_local3", LOG_LOCAL3},
    {"local4", LOG_LOCAL4},
    {"log_local4", LOG_LOCAL4},
    {"local5", LOG_LOCAL5},
    {"log_local5", LOG_LOCAL5},
    {"local6", LOG_LOCAL6},
    {"log_local6", LOG_LOCAL6},
    {"local7", LOG_LOCAL7},
    {"log_local7", LOG_LOCAL7},
    /* most of these likely make very little sense
       for us, but why not? */
    {"kern", LOG_KERN},
    {"log_kern", LOG_KERN},
    {"user", LOG_USER},
    {"log_user", LOG_USER},
    {"mail", LOG_MAIL},
    {"log_mail", LOG_MAIL},
    {"daemon", LOG_DAEMON},
    {"log_daemon", LOG_DAEMON},
    {"auth", LOG_AUTH},
    {"log_auth", LOG_AUTH},
    {"syslog", LOG_SYSLOG},
    {"log_syslog", LOG_SYSLOG},
    {"lpr", LOG_LPR},
    {"log_lpr", LOG_LPR},
    {"news", LOG_NEWS},
    {"log_news", LOG_NEWS},
    {"uucp", LOG_UUCP},
    {"log_uucp", LOG_UUCP},
    {"cron", LOG_CRON},
    {"log_cron", LOG_CRON},
    {"authpriv", LOG_AUTHPRIV},
    {"log_authpriv", LOG_AUTHPRIV},
    {"ftp", LOG_FTP},
    {"log_ftp", LOG_FTP}
  };

  toLowerInPlace(facilityStr);
  auto facilityIt = s_facilities.find(facilityStr);
  if (facilityIt == s_facilities.end()) {
    return std::nullopt;
  }

  return facilityIt->second;
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
  if (addr.empty()) {
    return -1;
  }

  string ourAddr(addr);
  std::optional<uint16_t> port = std::nullopt;

  if (addr[0] == '[') { // [::]:53 style address
    string::size_type pos = addr.find(']');
    if (pos == string::npos) {
      return -1;
    }

    ourAddr.assign(addr.c_str() + 1, pos - 1);
    if (pos + 1 != addr.size()) { // complete after ], no port specified
      if (pos + 2 > addr.size() || addr[pos + 1] != ':') {
        return -1;
      }

      try {
        auto tmpPort = pdns::checked_stoi<uint16_t>(addr.substr(pos + 2));
        port = std::make_optional(tmpPort);
      }
      catch (const std::out_of_range&) {
        return -1;
      }
    }
  }

  ret->sin6_scope_id = 0;
  ret->sin6_family = AF_INET6;

  if (inet_pton(AF_INET6, ourAddr.c_str(), (void*)&ret->sin6_addr) != 1) {
    struct addrinfo hints{};
    std::memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_INET6;

    struct addrinfo* res = nullptr;
    // getaddrinfo has anomalous return codes, anything nonzero is an error, positive or negative
    if (getaddrinfo(ourAddr.c_str(), nullptr, &hints, &res) != 0) {
      return -1;
    }

    memcpy(ret, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
  }

  if (port.has_value()) {
    ret->sin6_port = htons(*port);
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

  char *eptr = const_cast<char*>(str.c_str()) + str.size();
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
  auto filePtr = pdns::UniqueFilePtr(fopen(fname, "r"));
  if (!filePtr) {
    return false;
  }
  return stringfgets(filePtr.get(), *line);
}

Regex::Regex(const string& expr)
{
  if (auto ret = regcomp(&d_preg, expr.c_str(), REG_ICASE|REG_NOSUB|REG_EXTENDED); ret != 0) {
    std::array<char, 1024> errorBuffer{};
    if (regerror(ret, &d_preg, errorBuffer.data(), errorBuffer.size()) > 0) {
      throw PDNSException("Regular expression " + expr + " did not compile: " + errorBuffer.data());
    }
    throw PDNSException("Regular expression " + expr + " did not compile");
  }
}

// if you end up here because valgrind told you were are doing something wrong
// with msgh->msg_controllen, please refer to https://github.com/PowerDNS/pdns/pull/3962
// first.
// Note that cmsgbuf should be aligned the same as a struct cmsghdr
void addCMsgSrcAddr(struct msghdr* msgh, cmsgbuf_aligned* cmsgbuf, const ComboAddress* source, int itfIndex)
{
  struct cmsghdr *cmsg = nullptr;

  if(source->sin4.sin_family == AF_INET6) {
    struct in6_pktinfo *pkt;

    msgh->msg_control = cmsgbuf;
#if !defined( __APPLE__ )
    /* CMSG_SPACE is not a constexpr on macOS */
    static_assert(CMSG_SPACE(sizeof(*pkt)) <= sizeof(*cmsgbuf), "Buffer is too small for in6_pktinfo");
#else /* __APPLE__ */
    if (CMSG_SPACE(sizeof(*pkt)) > sizeof(*cmsgbuf)) {
      throw std::runtime_error("Buffer is too small for in6_pktinfo");
    }
#endif /* __APPLE__ */
    msgh->msg_controllen = CMSG_SPACE(sizeof(*pkt));

    cmsg = CMSG_FIRSTHDR(msgh);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

    pkt = (struct in6_pktinfo *) CMSG_DATA(cmsg);
    // Include the padding to stop valgrind complaining about passing uninitialized data
    memset(pkt, 0, CMSG_SPACE(sizeof(*pkt)));
    pkt->ipi6_addr = source->sin6.sin6_addr;
    pkt->ipi6_ifindex = itfIndex;
  }
  else {
#if defined(IP_PKTINFO)
    struct in_pktinfo *pkt;

    msgh->msg_control = cmsgbuf;
#if !defined( __APPLE__ )
    /* CMSG_SPACE is not a constexpr on macOS */
    static_assert(CMSG_SPACE(sizeof(*pkt)) <= sizeof(*cmsgbuf), "Buffer is too small for in_pktinfo");
#else /* __APPLE__ */
    if (CMSG_SPACE(sizeof(*pkt)) > sizeof(*cmsgbuf)) {
      throw std::runtime_error("Buffer is too small for in_pktinfo");
    }
#endif /* __APPLE__ */
    msgh->msg_controllen = CMSG_SPACE(sizeof(*pkt));

    cmsg = CMSG_FIRSTHDR(msgh);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));

    pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
    // Include the padding to stop valgrind complaining about passing uninitialized data
    memset(pkt, 0, CMSG_SPACE(sizeof(*pkt)));
    pkt->ipi_spec_dst = source->sin4.sin_addr;
    pkt->ipi_ifindex = itfIndex;
#elif defined(IP_SENDSRCADDR)
    struct in_addr *in;

    msgh->msg_control = cmsgbuf;
#if !defined( __APPLE__ )
    static_assert(CMSG_SPACE(sizeof(*in)) <= sizeof(*cmsgbuf), "Buffer is too small for in_addr");
#else /* __APPLE__ */
    if (CMSG_SPACE(sizeof(*in)) > sizeof(*cmsgbuf)) {
      throw std::runtime_error("Buffer is too small for in_addr");
    }
#endif /* __APPLE__ */
    msgh->msg_controllen = CMSG_SPACE(sizeof(*in));

    cmsg = CMSG_FIRSTHDR(msgh);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_SENDSRCADDR;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*in));

    // Include the padding to stop valgrind complaining about passing uninitialized data
    in = (struct in_addr *) CMSG_DATA(cmsg);
    memset(in, 0, CMSG_SPACE(sizeof(*in)));
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

bool setSocketTimestamps(int fd)
{
#ifdef SO_TIMESTAMP
  int on=1;
  return setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, (char*)&on, sizeof(on)) == 0;
#else
  return true; // we pretend this happened.
#endif
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

bool setReuseAddr(int sock)
{
  int tmp = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, static_cast<unsigned>(sizeof tmp))<0)
    throw PDNSException(string("Setsockopt failed: ")+stringerror());
  return true;
}

void setDscp(int sock, unsigned short family, uint8_t dscp)
{
  int val = 0;
  unsigned int len = 0;

  if (dscp == 0 || dscp > 63) {
    // No DSCP marking
    return;
  }

  if (family == AF_INET) {
    if (getsockopt(sock, IPPROTO_IP, IP_TOS, &val, &len)<0) {
      throw std::runtime_error(string("Set DSCP failed: ")+stringerror());
    }
    val = (dscp<<2) | (val&0x3);
    if (setsockopt(sock, IPPROTO_IP, IP_TOS, &val, sizeof(val))<0) {
      throw std::runtime_error(string("Set DSCP failed: ")+stringerror());
    }
  }
  else if (family == AF_INET6) {
    if (getsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &val, &len)<0) {
      throw std::runtime_error(string("Set DSCP failed: ")+stringerror());
    }
    val = (dscp<<2) | (val&0x3);
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val))<0) {
      throw std::runtime_error(string("Set DSCP failed: ")+stringerror());
    }
  }
}

bool isNonBlocking(int sock)
{
  int flags=fcntl(sock,F_GETFL,0);
  return flags & O_NONBLOCK;
}

bool setReceiveSocketErrors([[maybe_unused]] int sock, [[maybe_unused]] int af)
{
#ifdef __linux__
  int tmp = 1, ret;
  if (af == AF_INET) {
    ret = setsockopt(sock, IPPROTO_IP, IP_RECVERR, &tmp, sizeof(tmp));
  } else {
    ret = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVERR, &tmp, sizeof(tmp));
  }
  if (ret < 0) {
    throw PDNSException(string("Setsockopt failed: ") + stringerror());
  }
#endif
  return true;
}

// Closes a socket.
int closesocket(int socket)
{
  int ret = ::close(socket);
  if(ret < 0 && errno == ECONNRESET) { // see ticket 192, odd BSD behaviour
    return 0;
  }
  if (ret < 0) {
    int err = errno;
    throw PDNSException("Error closing socket: " + stringerror(err));
  }
  return ret;
}

bool setCloseOnExec(int sock)
{
  int flags=fcntl(sock,F_GETFD,0);
  if(flags<0 || fcntl(sock, F_SETFD,flags|FD_CLOEXEC) <0)
    return false;
  return true;
}

#ifdef __linux__
#include <linux/rtnetlink.h>

int getMACAddress(const ComboAddress& ca, char* dest, size_t destLen)
{
  struct {
    struct nlmsghdr headermsg;
    struct ndmsg neighbormsg;
  } request;

  std::array<char, 8192> buffer;

  auto sock = FDWrapper(socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE));
  if (sock.getHandle() == -1) {
    return errno;
  }

  memset(&request, 0, sizeof(request));
  request.headermsg.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
  request.headermsg.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.headermsg.nlmsg_type = RTM_GETNEIGH;
  request.neighbormsg.ndm_family = ca.sin4.sin_family;

  while (true) {
    ssize_t sent = send(sock.getHandle(), &request, sizeof(request), 0);
    if (sent == -1) {
      if (errno == EINTR) {
        continue;
      }
      return errno;
    }
    else if (static_cast<size_t>(sent) != sizeof(request)) {
      return EIO;
    }
    break;
  }

  bool done = false;
  bool foundIP = false;
  bool foundMAC = false;
  do {
    ssize_t got = recv(sock.getHandle(), buffer.data(), buffer.size(), 0);

    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      return errno;
    }

    size_t remaining = static_cast<size_t>(got);
    for (struct nlmsghdr* nlmsgheader = reinterpret_cast<struct nlmsghdr*>(buffer.data());
         done == false && NLMSG_OK (nlmsgheader, remaining);
         nlmsgheader = reinterpret_cast<struct nlmsghdr*>(NLMSG_NEXT(nlmsgheader, remaining))) {

      if (nlmsgheader->nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }

      auto nd = reinterpret_cast<struct ndmsg*>(NLMSG_DATA(nlmsgheader));
      auto rtatp = reinterpret_cast<struct rtattr*>(reinterpret_cast<char*>(nd) + NLMSG_ALIGN(sizeof(struct ndmsg)));
      int rtattrlen = nlmsgheader->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));

      if (nd->ndm_family != ca.sin4.sin_family) {
        continue;
      }

      if (ca.sin4.sin_family == AF_INET6 && ca.sin6.sin6_scope_id != 0 && static_cast<int32_t>(ca.sin6.sin6_scope_id) != nd->ndm_ifindex) {
        continue;
      }

      for (; done == false && RTA_OK(rtatp, rtattrlen); rtatp = RTA_NEXT(rtatp, rtattrlen)) {
        if (rtatp->rta_type == NDA_DST){
          if (nd->ndm_family == AF_INET) {
            auto inp = reinterpret_cast<struct in_addr*>(RTA_DATA(rtatp));
            if (inp->s_addr == ca.sin4.sin_addr.s_addr) {
              foundIP = true;
            }
          }
          else if (nd->ndm_family == AF_INET6) {
            auto inp = reinterpret_cast<struct in6_addr *>(RTA_DATA(rtatp));
            if (memcmp(inp->s6_addr, ca.sin6.sin6_addr.s6_addr, sizeof(ca.sin6.sin6_addr.s6_addr)) == 0) {
              foundIP = true;
            }
          }
        }
        else if (rtatp->rta_type == NDA_LLADDR) {
          if (foundIP) {
            size_t addrLen = rtatp->rta_len - sizeof(struct rtattr);
            if (addrLen > destLen) {
              return ENOBUFS;
            }
            memcpy(dest, reinterpret_cast<const char*>(rtatp) + sizeof(struct rtattr), addrLen);
            foundMAC = true;
            done = true;
            break;
          }
        }
      }
    }
  }
  while (done == false);

  return foundMAC ? 0 : ENOENT;
}
#else
int getMACAddress(const ComboAddress& /* ca */, char* /* dest */, size_t /* len */)
{
  return ENOENT;
}
#endif /* __linux__ */

string getMACAddress(const ComboAddress& ca)
{
  string ret;
  char tmp[6];
  if (getMACAddress(ca, tmp, sizeof(tmp)) == 0) {
    ret.append(tmp, sizeof(tmp));
  }
  return ret;
}

uint64_t udpErrorStats([[maybe_unused]] const std::string& str)
{
#ifdef __linux__
  ifstream ifs("/proc/net/snmp");
  if (!ifs) {
    return 0;
  }

  string line;
  while (getline(ifs, line)) {
    if (boost::starts_with(line, "Udp: ") && isdigit(line.at(5))) {
      vector<string> parts;
      stringtok(parts, line, " \n\t\r");

      if (parts.size() < 7) {
        break;
      }

      if (str == "udp-rcvbuf-errors") {
        return std::stoull(parts.at(5));
      }
      else if (str == "udp-sndbuf-errors") {
        return std::stoull(parts.at(6));
      }
      else if (str == "udp-noport-errors") {
        return std::stoull(parts.at(2));
      }
      else if (str == "udp-in-errors") {
        return std::stoull(parts.at(3));
      }
      else if (parts.size() >= 8 && str == "udp-in-csum-errors") {
        return std::stoull(parts.at(7));
      }
      else {
        return 0;
      }
    }
  }
#endif
  return 0;
}

uint64_t udp6ErrorStats([[maybe_unused]] const std::string& str)
{
#ifdef __linux__
  const std::map<std::string, std::string> keys = {
    { "udp6-in-errors", "Udp6InErrors" },
    { "udp6-recvbuf-errors", "Udp6RcvbufErrors" },
    { "udp6-sndbuf-errors", "Udp6SndbufErrors" },
    { "udp6-noport-errors", "Udp6NoPorts" },
    { "udp6-in-csum-errors", "Udp6InCsumErrors" }
  };

  auto key = keys.find(str);
  if (key == keys.end()) {
    return 0;
  }

  ifstream ifs("/proc/net/snmp6");
  if (!ifs) {
    return 0;
  }

  std::string line;
  while (getline(ifs, line)) {
    if (!boost::starts_with(line, key->second)) {
      continue;
    }

    std::vector<std::string> parts;
    stringtok(parts, line, " \n\t\r");

    if (parts.size() != 2) {
      return 0;
    }

    return std::stoull(parts.at(1));
  }
#endif
  return 0;
}

uint64_t tcpErrorStats(const std::string& /* str */)
{
#ifdef __linux__
  ifstream ifs("/proc/net/netstat");
  if (!ifs) {
    return 0;
  }

  string line;
  vector<string> parts;
  while (getline(ifs,line)) {
    if (line.size() > 9 && boost::starts_with(line, "TcpExt: ") && isdigit(line.at(8))) {
      stringtok(parts, line, " \n\t\r");

      if (parts.size() < 21) {
        break;
      }

      return std::stoull(parts.at(20));
    }
  }
#endif
  return 0;
}

uint64_t getCPUIOWait(const std::string& /* str */)
{
#ifdef __linux__
  ifstream ifs("/proc/stat");
  if (!ifs) {
    return 0;
  }

  string line;
  vector<string> parts;
  while (getline(ifs, line)) {
    if (boost::starts_with(line, "cpu ")) {
      stringtok(parts, line, " \n\t\r");

      if (parts.size() < 6) {
        break;
      }

      return std::stoull(parts[5]);
    }
  }
#endif
  return 0;
}

uint64_t getCPUSteal(const std::string& /* str */)
{
#ifdef __linux__
  ifstream ifs("/proc/stat");
  if (!ifs) {
    return 0;
  }

  string line;
  vector<string> parts;
  while (getline(ifs, line)) {
    if (boost::starts_with(line, "cpu ")) {
      stringtok(parts, line, " \n\t\r");

      if (parts.size() < 9) {
        break;
      }

      return std::stoull(parts[8]);
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
  uint64_t nbFileDescriptors = 0;
  const auto dirName = "/proc/" + std::to_string(getpid()) + "/fd/";
  auto directoryError = pdns::visit_directory(dirName, [&nbFileDescriptors]([[maybe_unused]] ino_t inodeNumber, const std::string_view& name) {
    uint32_t num;
    try {
      pdns::checked_stoi_into(num, std::string(name));
      if (std::to_string(num) == name) {
        nbFileDescriptors++;
      }
    } catch (...) {
      // was not a number.
    }
    return true;
  });
  if (directoryError) {
    return 0U;
  }
  return nbFileDescriptors;
#elif defined(__OpenBSD__)
  // FreeBSD also has this in libopenbsd, but I don't know if that's available always
  return getdtablecount();
#else
  return 0U;
#endif
}

uint64_t getRealMemoryUsage(const std::string&)
{
#ifdef __linux__
  ifstream ifs("/proc/self/statm");
  if(!ifs)
    return 0;

  uint64_t size, resident, shared, text, lib, data;
  ifs >> size >> resident >> shared >> text >> lib >> data;

  // We used to use "data" here, but it proves unreliable and even is marked "broken"
  // in https://www.kernel.org/doc/html/latest/filesystems/proc.html
  return resident * getpagesize();
#else
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) != 0)
    return 0;
  return ru.ru_maxrss * 1024;
#endif
}


uint64_t getSpecialMemoryUsage(const std::string&)
{
#ifdef __linux__
  ifstream ifs("/proc/self/smaps");
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
  auto seconds = second.tv_sec - first.tv_sec;
  auto nseconds = second.tv_nsec - first.tv_nsec;

  if (nseconds < 0) {
    seconds -= 1;
    nseconds += 1000000000;
  }
  return static_cast<double>(seconds) + static_cast<double>(nseconds) / 1000000000.0;
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

  if (pwd == nullptr) {
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

  if (grp == nullptr) {
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

bool isSettingThreadCPUAffinitySupported()
{
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  return true;
#else
  return false;
#endif
}

int mapThreadToCPUList([[maybe_unused]] pthread_t tid, [[maybe_unused]] const std::set<int>& cpus)
{
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
#  ifdef __NetBSD__
  cpuset_t *cpuset;
  cpuset = cpuset_create();
  for (const auto cpuID : cpus) {
    cpuset_set(cpuID, cpuset);
  }

  return pthread_setaffinity_np(tid,
                                cpuset_size(cpuset),
                                cpuset);
#  else
#    ifdef __FreeBSD__
#      define cpu_set_t cpuset_t
#    endif
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  for (const auto cpuID : cpus) {
    CPU_SET(cpuID, &cpuset);
  }

  return pthread_setaffinity_np(tid,
                                sizeof(cpuset),
                                &cpuset);
#  endif
#else
  return ENOSYS;
#endif /* HAVE_PTHREAD_SETAFFINITY_NP */
}

std::vector<ComboAddress> getResolvers(const std::string& resolvConfPath)
{
  std::vector<ComboAddress> results;

  ifstream ifs(resolvConfPath);
  if (!ifs) {
    return results;
  }

  string line;
  while(std::getline(ifs, line)) {
    boost::trim_right_if(line, boost::is_any_of(" \r\n\x1a"));
    boost::trim_left(line); // leading spaces, let's be nice

    string::size_type tpos = line.find_first_of(";#");
    if (tpos != string::npos) {
      line.resize(tpos);
    }

    if (boost::starts_with(line, "nameserver ") || boost::starts_with(line, "nameserver\t")) {
      vector<string> parts;
      stringtok(parts, line, " \t,"); // be REALLY nice
      for (auto iter = parts.begin() + 1; iter != parts.end(); ++iter) {
        try {
          results.emplace_back(*iter, 53);
        }
        catch(...)
        {
        }
      }
    }
  }

  return results;
}

size_t getPipeBufferSize([[maybe_unused]] int fd)
{
#ifdef F_GETPIPE_SZ
  int res = fcntl(fd, F_GETPIPE_SZ);
  if (res == -1) {
    return 0;
  }
  return res;
#else
  errno = ENOSYS;
  return 0;
#endif /* F_GETPIPE_SZ */
}

bool setPipeBufferSize([[maybe_unused]] int fd, [[maybe_unused]] size_t size)
{
#ifdef F_SETPIPE_SZ
  if (size > static_cast<size_t>(std::numeric_limits<int>::max())) {
    errno = EINVAL;
    return false;
  }
  int newSize = static_cast<int>(size);
  int res = fcntl(fd, F_SETPIPE_SZ, newSize);
  if (res == -1) {
    return false;
  }
  return true;
#else
  errno = ENOSYS;
  return false;
#endif /* F_SETPIPE_SZ */
}

DNSName reverseNameFromIP(const ComboAddress& ip)
{
  if (ip.isIPv4()) {
    std::string result("in-addr.arpa.");
    auto ptr = reinterpret_cast<const uint8_t*>(&ip.sin4.sin_addr.s_addr);
    for (size_t idx = 0; idx < sizeof(ip.sin4.sin_addr.s_addr); idx++) {
      result = std::to_string(ptr[idx]) + "." + result;
    }
    return DNSName(result);
  }
  else if (ip.isIPv6()) {
    std::string result("ip6.arpa.");
    auto ptr = reinterpret_cast<const uint8_t*>(&ip.sin6.sin6_addr.s6_addr[0]);
    for (size_t idx = 0; idx < sizeof(ip.sin6.sin6_addr.s6_addr); idx++) {
      std::stringstream stream;
      stream << std::hex << (ptr[idx] & 0x0F);
      stream << '.';
      stream << std::hex << (((ptr[idx]) >> 4) & 0x0F);
      stream << '.';
      result = stream.str() + result;
    }
    return DNSName(result);
  }

  throw std::runtime_error("Calling reverseNameFromIP() for an address which is neither an IPv4 nor an IPv6");
}

std::string makeLuaString(const std::string& in)
{
  ostringstream str;

  str<<'"';

  char item[5];
  for (unsigned char n : in) {
    if (islower(n) || isupper(n)) {
      item[0] = n;
      item[1] = 0;
    }
    else {
      snprintf(item, sizeof(item), "\\%03d", n);
    }
    str << item;
  }

  str<<'"';

  return str.str();
}

size_t parseSVCBValueList(const std::string &in, vector<std::string> &val) {
  std::string parsed;
  auto ret = parseRFC1035CharString(in, parsed);
  parseSVCBValueListFromParsedRFC1035CharString(parsed, val);
  return ret;
};

#ifdef HAVE_CRYPTO_MEMCMP
#include <openssl/crypto.h>
#else /* HAVE_CRYPTO_MEMCMP */
#ifdef HAVE_SODIUM_MEMCMP
#include <sodium.h>
#endif /* HAVE_SODIUM_MEMCMP */
#endif /* HAVE_CRYPTO_MEMCMP */

bool constantTimeStringEquals(const std::string& a, const std::string& b)
{
  if (a.size() != b.size()) {
    return false;
  }
  const size_t size = a.size();
#ifdef HAVE_CRYPTO_MEMCMP
  return CRYPTO_memcmp(a.c_str(), b.c_str(), size) == 0;
#else /* HAVE_CRYPTO_MEMCMP */
#ifdef HAVE_SODIUM_MEMCMP
  return sodium_memcmp(a.c_str(), b.c_str(), size) == 0;
#else /* HAVE_SODIUM_MEMCMP */
  const volatile unsigned char *_a = (const volatile unsigned char *) a.c_str();
  const volatile unsigned char *_b = (const volatile unsigned char *) b.c_str();
  unsigned char res = 0;

  for (size_t idx = 0; idx < size; idx++) {
    res |= _a[idx] ^ _b[idx];
  }

  return res == 0;
#endif /* !HAVE_SODIUM_MEMCMP */
#endif /* !HAVE_CRYPTO_MEMCMP */
}

namespace pdns
{
struct CloseDirDeleter
{
  void operator()(DIR* dir) const noexcept {
    closedir(dir);
  }
};

std::optional<std::string> visit_directory(const std::string& directory, const std::function<bool(ino_t inodeNumber, const std::string_view& name)>& visitor)
{
  auto dirHandle = std::unique_ptr<DIR, CloseDirDeleter>(opendir(directory.c_str()));
  if (!dirHandle) {
    auto err = errno;
    return std::string("Error opening directory '" + directory + "': " + stringerror(err));
  }

  bool keepGoing = true;
  struct dirent* ent = nullptr;
  // NOLINTNEXTLINE(concurrency-mt-unsafe): readdir is thread-safe nowadays and readdir_r is deprecated
  while (keepGoing && (ent = readdir(dirHandle.get())) != nullptr) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay: dirent API
    auto name = std::string_view(ent->d_name, strlen(ent->d_name));
    keepGoing = visitor(ent->d_ino, name);
  }

  return std::nullopt;
}

UniqueFilePtr openFileForWriting(const std::string& filePath, mode_t permissions, bool mustNotExist, bool appendIfExists)
{
  int flags = O_WRONLY | O_CREAT;
  if (mustNotExist) {
    flags |= O_EXCL;
  }
  else if (appendIfExists) {
    flags |= O_APPEND;
  }
  int fileDesc = open(filePath.c_str(), flags, permissions);
  if (fileDesc == -1) {
    return {};
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(fileDesc, appendIfExists ? "a" : "w"));
  if (!filePtr) {
    auto error = errno;
    close(fileDesc);
    errno = error;
    return {};
  }
  return filePtr;
}

}
