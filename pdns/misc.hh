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
#pragma once
#include <inttypes.h>
#include <cstring>
#include <cstdio>
#include <regex.h>
#include <limits.h>
#include <type_traits>
#include <boost/algorithm/string.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>

using namespace ::boost::multi_index;

#include "dns.hh"
#include <atomic>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <syslog.h>
#include <deque>
#include <stdexcept>
#include <string>
#include <ctype.h>
#include <vector>

#include "namespaces.hh"
#include "dnsname.hh"

typedef enum { TSIG_MD5, TSIG_SHA1, TSIG_SHA224, TSIG_SHA256, TSIG_SHA384, TSIG_SHA512, TSIG_GSS } TSIGHashEnum;

string nowTime();
const string unquotify(const string &item);
string humanDuration(time_t passed);
bool stripDomainSuffix(string *qname, const string &domain);
void stripLine(string &line);
string getHostname();
string urlEncode(const string &text);
int waitForData(int fd, int seconds, int useconds=0);
int waitFor2Data(int fd1, int fd2, int seconds, int useconds, int* fd);
int waitForMultiData(const set<int>& fds, const int seconds, const int useconds, int* fd);
int waitForRWData(int fd, bool waitForRead, int seconds, int useconds, bool* error=nullptr, bool* disconnected=nullptr);
uint16_t getShort(const unsigned char *p);
uint16_t getShort(const char *p);
uint32_t getLong(const unsigned char *p);
uint32_t getLong(const char *p);
bool getTSIGHashEnum(const DNSName& algoName, TSIGHashEnum& algoEnum);
DNSName getTSIGAlgoName(TSIGHashEnum& algoEnum);

int logFacilityToLOG(unsigned int facility);

struct ServiceTuple
{
  string host;
  uint16_t port;
};
void parseService(const string &descr, ServiceTuple &st);

template <typename Container>
void
stringtok (Container &container, string const &in,
           const char * const delimiters = " \t\n")
{
  const string::size_type len = in.length();
  string::size_type i = 0;

  while (i<len) {
    // eat leading whitespace
    i = in.find_first_not_of (delimiters, i);
    if (i == string::npos)
      return;   // nothing left but white space

    // find the end of the token
    string::size_type j = in.find_first_of (delimiters, i);

    // push token
    if (j == string::npos) {
      container.push_back (in.substr(i));
      return;
    } else
      container.push_back (in.substr(i, j-i));

    // set up for next loop
    i = j + 1;
  }
}

template<typename T> bool rfc1982LessThan(T a, T b)
{
  static_assert(std::is_unsigned<T>::value, "rfc1982LessThan only works for unsigned types");
  typedef typename std::make_signed<T>::type signed_t;
  return static_cast<signed_t>(a - b) < 0;
}

// fills container with ranges, so {posbegin,posend}
template <typename Container>
void
vstringtok (Container &container, string const &in,
           const char * const delimiters = " \t\n")
{
  const string::size_type len = in.length();
  string::size_type i = 0;

  while (i<len) {
    // eat leading whitespace
    i = in.find_first_not_of (delimiters, i);
    if (i == string::npos)
      return;   // nothing left but white space

    // find the end of the token
    string::size_type j = in.find_first_of (delimiters, i);

    // push token
    if (j == string::npos) {
      container.push_back (make_pair(i, len));
      return;
    } else
      container.push_back (make_pair(i, j));

    // set up for next loop
    i = j + 1;
  }
}

size_t writen2(int fd, const void *buf, size_t count);
inline size_t writen2(int fd, const std::string &s) { return writen2(fd, s.data(), s.size()); }
size_t readn2(int fd, void* buffer, size_t len);
size_t readn2WithTimeout(int fd, void* buffer, size_t len, int idleTimeout, int totalTimeout=0);
size_t writen2WithTimeout(int fd, const void * buffer, size_t len, int timeout);

const string toLower(const string &upper);
const string toLowerCanonic(const string &upper);
bool IpToU32(const string &str, uint32_t *ip);
string U32ToIP(uint32_t);
string stringerror(int);
string stringerror();
string itoa(int i);
string uitoa(unsigned int i);
string bitFlip(const string &str);

void dropPrivs(int uid, int gid);
void cleanSlashes(string &str);

#if defined(_POSIX_THREAD_CPUTIME) && defined(CLOCK_THREAD_CPUTIME_ID)
/** CPUTime measurements */
class CPUTime
{
public:
  void start()
  {
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &d_start);
  }
  uint64_t ndiff()
  {
    struct timespec now;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
    return 1000000000ULL*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec);
  }
private:
  struct timespec d_start;
};
#endif

/** The DTime class can be used for timing statistics with microsecond resolution.
On 32 bits systems this means that 2147 seconds is the longest time that can be measured. */
class DTime
{
public:
  DTime(); //!< Does not set the timer for you! Saves lots of gettimeofday() calls
  DTime(const DTime &dt) = default;
  DTime & operator=(const DTime &dt) = default;
  time_t time();
  inline void set();  //!< Reset the timer
  inline int udiff(); //!< Return the number of microseconds since the timer was last set.
  inline int udiffNoReset(); //!< Return the number of microseconds since the timer was last set.
  void setTimeval(const struct timeval& tv)
  {
    d_set=tv;
  }
  struct timeval getTimeval()
  {
    return d_set;
  }
private:
  struct timeval d_set;
};

inline void DTime::set()
{
  gettimeofday(&d_set,0);
}

inline int DTime::udiff()
{
  int res=udiffNoReset();
  gettimeofday(&d_set,0);
  return res;
}

inline int DTime::udiffNoReset()
{
  struct timeval now;

  gettimeofday(&now,0);
  int ret=1000000*(now.tv_sec-d_set.tv_sec)+(now.tv_usec-d_set.tv_usec);
  return ret;
}

inline const string toLower(const string &upper)
{
  string reply(upper);
  const size_t length = reply.length();
  char c;
  for(unsigned int i = 0; i < length; ++i) {
    c = dns_tolower(upper[i]);
    if( c != upper[i])
      reply[i] = c;
  }
  return reply;
}

inline const string toLowerCanonic(const string &upper)
{
  string reply(upper);
  if(!upper.empty()) {
    unsigned int i, limit= ( unsigned int ) reply.length();
    unsigned char c;
    for(i = 0; i < limit ; i++) {
      c = dns_tolower(upper[i]);
      if(c != upper[i])
        reply[i] = c;
    }
    if(upper[i-1]=='.')
      reply.resize(i-1);
  }

  return reply;
}



// Make s uppercase:
inline string toUpper( const string& s )
{
        string r(s);
        for( unsigned int i = 0; i < s.length(); i++ ) {
          r[i] = dns_toupper(r[i]);
        }
        return r;
}

inline double getTime()
{
  struct timeval now;
  gettimeofday(&now,0);

  return now.tv_sec+now.tv_usec/1000000.0;
}

inline void unixDie(const string &why)
{
  throw runtime_error(why+": "+stringerror());
}

string makeHexDump(const string& str);
struct DNSRecord;
struct DNSZoneRecord;
void shuffle(vector<DNSRecord>& rrs);
void shuffle(vector<DNSZoneRecord>& rrs);

void orderAndShuffle(vector<DNSRecord>& rrs);

void normalizeTV(struct timeval& tv);
const struct timeval operator+(const struct timeval& lhs, const struct timeval& rhs);
const struct timeval operator-(const struct timeval& lhs, const struct timeval& rhs);
inline float makeFloat(const struct timeval& tv)
{
  return tv.tv_sec + tv.tv_usec/1000000.0f;
}

inline bool operator<(const struct timeval& lhs, const struct timeval& rhs)
{
  return make_pair(lhs.tv_sec, lhs.tv_usec) < make_pair(rhs.tv_sec, rhs.tv_usec);
}

inline bool operator<(const struct timespec& lhs, const struct timespec& rhs)
{
  return tie(lhs.tv_sec, lhs.tv_nsec) < tie(rhs.tv_sec, rhs.tv_nsec);
}


inline bool pdns_ilexicographical_compare(const std::string& a, const std::string& b)  __attribute__((pure));
inline bool pdns_ilexicographical_compare(const std::string& a, const std::string& b)
{
  const unsigned char *aPtr = (const unsigned char*)a.c_str(), *bPtr = (const unsigned char*)b.c_str();
  const unsigned char *aEptr = aPtr + a.length(), *bEptr = bPtr + b.length();
  while(aPtr != aEptr && bPtr != bEptr) {
    if ((*aPtr != *bPtr) && (dns_tolower(*aPtr) - dns_tolower(*bPtr)))
      return (dns_tolower(*aPtr) - dns_tolower(*bPtr)) < 0;
    aPtr++;
    bPtr++;
  }
  if(aPtr == aEptr && bPtr == bEptr) // strings are equal (in length)
    return false;
  return aPtr == aEptr; // true if first string was shorter
}

inline bool pdns_iequals(const std::string& a, const std::string& b) __attribute__((pure));
inline bool pdns_iequals(const std::string& a, const std::string& b)
{
  if (a.length() != b.length())
    return false;

  const char *aPtr = a.c_str(), *bPtr = b.c_str();
  const char *aEptr = aPtr + a.length();
  while(aPtr != aEptr) {
    if((*aPtr != *bPtr) && (dns_tolower(*aPtr) != dns_tolower(*bPtr)))
      return false;
    aPtr++;
    bPtr++;
  }
  return true;
}

inline bool pdns_iequals_ch(const char a, const char b) __attribute__((pure));
inline bool pdns_iequals_ch(const char a, const char b)
{
  if ((a != b) && (dns_tolower(a) != dns_tolower(b)))
    return false;

  return true;
}


typedef unsigned long AtomicCounterInner;
typedef std::atomic<AtomicCounterInner> AtomicCounter ;

// FIXME400 this should probably go? 
struct CIStringCompare: public std::binary_function<string, string, bool>
{
  bool operator()(const string& a, const string& b) const
  {
    return pdns_ilexicographical_compare(a, b);
  }
};

struct CIStringComparePOSIX
{
   bool operator() (const std::string& lhs, const std::string& rhs)
   {
      std::string::const_iterator a,b;
      const std::locale &loc = std::locale("POSIX");
      a=lhs.begin();b=rhs.begin();
      while(a!=lhs.end()) {
          if (b==rhs.end() || std::tolower(*b,loc)<std::tolower(*a,loc)) return false;
          else if (std::tolower(*a,loc)<std::tolower(*b,loc)) return true;
          ++a;++b;
      }
      return (b!=rhs.end());
   }
};

struct CIStringPairCompare: public std::binary_function<pair<string, uint16_t>, pair<string,uint16_t>, bool>
{
  bool operator()(const pair<string, uint16_t>& a, const pair<string, uint16_t>& b) const
  {
    if(pdns_ilexicographical_compare(a.first, b.first))
	return true;
    if(pdns_ilexicographical_compare(b.first, a.first))
	return false;
    return a.second < b.second;
  }
};

inline size_t pdns_ci_find(const string& haystack, const string& needle)
{
  string::const_iterator it = std::search(haystack.begin(), haystack.end(),
    needle.begin(), needle.end(), pdns_iequals_ch);
  if (it == haystack.end()) {
    // not found
    return string::npos;
  } else {
    return it - haystack.begin();
  }
}

pair<string, string> splitField(const string& inp, char sepa);

inline bool isCanonical(const string& qname)
{
  if(qname.empty())
    return false;
  return qname[qname.size()-1]=='.';
}

inline DNSName toCanonic(const DNSName& zone, const string& qname)
{
  if(qname.size()==1 && qname[0]=='@')
    return zone;
  if(isCanonical(qname))
    return DNSName(qname);
  return DNSName(qname) += zone;
}

string stripDot(const string& dom);

int makeIPv6sockaddr(const std::string& addr, struct sockaddr_in6* ret);
int makeIPv4sockaddr(const std::string& str, struct sockaddr_in* ret);
int makeUNsockaddr(const std::string& path, struct sockaddr_un* ret);
bool stringfgets(FILE* fp, std::string& line);

template<typename Index>
std::pair<typename Index::iterator,bool>
replacing_insert(Index& i,const typename Index::value_type& x)
{
  std::pair<typename Index::iterator,bool> res=i.insert(x);
  if(!res.second)res.second=i.replace(res.first,x);
  return res;
}

/** very small regex wrapper */
class Regex
{
public:
  /** constructor that accepts the expression to regex */
  Regex(const string &expr);

  ~Regex()
  {
    regfree(&d_preg);
  }
  /** call this to find out if 'line' matches your expression */
  bool match(const string &line) const
  {
    return regexec(&d_preg,line.c_str(),0,0,0)==0;
  }
  bool match(const DNSName& name) const
  {
    return match(name.toStringNoDot());
  }

private:
  regex_t d_preg;
};

class SimpleMatch
{
public:
  SimpleMatch(const string &mask, bool caseFold = false): d_mask(mask), d_fold(caseFold)
  {
  }
 
  bool match(string::const_iterator mi, string::const_iterator mend, string::const_iterator vi, string::const_iterator vend)
  {
    for(;;++mi) {
      if (mi == mend) {
        return vi == vend;
      } else if (*mi == '?') {
        if (vi == vend) return false;
        ++vi;
      } else if (*mi == '*') {
        while(*mi == '*') ++mi;
        if (mi == d_mask.end()) return true;
        while(vi != vend) {
          if (match(mi,mend,vi,vend)) return true;
          ++vi;
        }
        return false;
      } else {
        if ((mi == mend && vi != vend)||
            (mi != mend && vi == vend)) return false;
        if (d_fold) {
          if (dns_tolower(*mi) != dns_tolower(*vi)) return false;
        } else {
          if (*mi != *vi) return false;
        }
        ++vi;
      }
    }
  }

  bool match(const string& value) {
    return match(d_mask.begin(), d_mask.end(), value.begin(), value.end());
  }

  bool match(const DNSName& name) {
    return match(name.toStringNoDot());
  }

private:
  string d_mask;
  bool d_fold;
};

union ComboAddress;

// An aligned type to hold cmsgbufs. See https://man.openbsd.org/CMSG_DATA
typedef union { struct cmsghdr hdr; char buf[256]; } cmsgbuf_aligned;

/* itfIndex is an interface index, as returned by if_nametoindex(). 0 means default. */
void addCMsgSrcAddr(struct msghdr* msgh, cmsgbuf_aligned* cbuf, const ComboAddress* source, int itfIndex);

unsigned int getFilenumLimit(bool hardOrSoft=0);
void setFilenumLimit(unsigned int lim);
bool readFileIfThere(const char* fname, std::string* line);
uint32_t burtle(const unsigned char* k, uint32_t length, uint32_t init);
bool setSocketTimestamps(int fd);

//! Sets the socket into blocking mode.
bool setBlocking( int sock );

//! Sets the socket into non-blocking mode.
bool setNonBlocking( int sock );
bool setTCPNoDelay(int sock);
bool setReuseAddr(int sock);
bool isNonBlocking(int sock);
bool setReceiveSocketErrors(int sock, int af);
int closesocket(int fd);
bool setCloseOnExec(int sock);

size_t getPipeBufferSize(int fd);
bool setPipeBufferSize(int fd, size_t size);

uint64_t udpErrorStats(const std::string& str);
uint64_t getRealMemoryUsage(const std::string&);
uint64_t getSpecialMemoryUsage(const std::string&);
uint64_t getOpenFileDescriptors(const std::string&);
uint64_t getCPUTimeUser(const std::string&);
uint64_t getCPUTimeSystem(const std::string&);
std::string getMACAddress(const ComboAddress& ca);
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}


template<typename T>
const T& defTer(const T& a, const T& b)
{
  return a ? a : b;
}

template<typename P, typename T>
T valueOrEmpty(const P val) {
  if (!val) return T{};
  return T(val);
}


// I'm not very OCD, but I appreciate loglines like "processing 1 delta", "processing 2 deltas" :-)
template <typename Integer>
const char* addS(Integer siz, typename std::enable_if<std::is_integral<Integer>::value>::type*P=0)
{
  if(!siz || siz > 1)
    return "s";
  else return "";
}

template<typename C>
const char* addS(const C& c, typename std::enable_if<std::is_class<C>::value>::type*P=0)
{
  return addS(c.size());
}

template<typename C>
const typename C::value_type::second_type* rplookup(const C& c, const typename C::value_type::first_type& key)
{
  auto fnd = c.find(key);
  if(fnd == c.end())
    return 0;
  return &fnd->second;
}

double DiffTime(const struct timespec& first, const struct timespec& second);
double DiffTime(const struct timeval& first, const struct timeval& second);
uid_t strToUID(const string &str);
gid_t strToGID(const string &str);

unsigned int pdns_stou(const std::string& str, size_t * idx = 0, int base = 10);

bool isSettingThreadCPUAffinitySupported();
int mapThreadToCPUList(pthread_t tid, const std::set<int>& cpus);

std::vector<ComboAddress> getResolvers(const std::string& resolvConfPath);
