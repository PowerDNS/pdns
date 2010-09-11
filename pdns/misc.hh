/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2009  PowerDNS.COM BV

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
#ifndef MISC_HH
#define MISC_HH
#include <inttypes.h>
#include <cstring>
#include <cstdio>
#include <boost/algorithm/string.hpp>
#if 0
#include <iostream>
using std::cout;
using std::endl;

struct TSCTimer
{
  TSCTimer()
  {
    RDTSC(d_tsc1);
  }
  ~TSCTimer()
  {
    uint64_t tsc2;
    RDTSC(tsc2);
    cout<<"Timer: "<< (tsc2 - d_tsc1)/3000.0 << endl;
  }
  uint64_t d_tsc1;
};
#endif

#include "utility.hh"
#include "dns.hh"
#ifndef WIN32
# include <sys/time.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <time.h>
# include <syslog.h>
#else
# define WINDOWS_LEAN_AND_MEAN
# include <windows.h>
# include "utility.hh"
#endif // WIN32
#include <deque>
#include <stdexcept>
#include <string>
#include <ctype.h>
#include <vector>
#include <boost/optional.hpp>

using namespace std;
bool chopOff(string &domain);
bool chopOffDotted(string &domain);

bool endsOn(const string &domain, const string &suffix);
bool dottedEndsOn(const string &domain, const string &suffix);
string nowTime();
const string unquotify(const string &item);
string humanDuration(time_t passed);
void chomp(string &line, const string &delim);
bool stripDomainSuffix(string *qname, const string &domain);
void stripLine(string &line);
string getHostname();
string urlEncode(const string &text);
int waitForData(int fd, int seconds, int useconds=0);
int waitForRWData(int fd, bool waitForRead, int seconds, int useconds);
uint16_t getShort(const unsigned char *p);
uint16_t getShort(const char *p);
uint32_t getLong(const unsigned char *p);
uint32_t getLong(const char *p);
boost::optional<int> logFacilityToLOG(unsigned int facility);

inline void putLong(unsigned char* p, uint32_t val)
{
  *p++=(val>>24)&0xff;
  *p++=(val>>16)&0xff;
  *p++=(val>>8)&0xff;
  *p++=(val   )&0xff;

}
inline void putLong(char* p, uint32_t val)
{
  putLong((unsigned char *)p,val);
}


inline uint32_t getLong(unsigned char *p)
{
  return (p[0]<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
}


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

int writen2(int fd, const void *buf, size_t count);
inline int writen2(int fd, const std::string &s) { return writen2(fd, s.data(), s.size()); }


const string toLower(const string &upper);
const string toLowerCanonic(const string &upper);
bool IpToU32(const string &str, uint32_t *ip);
string U32ToIP(uint32_t);
string stringerror();
string netstringerror();
string itoa(int i);
string uitoa(unsigned int i);

void dropPrivs(int uid, int gid);
int makeGidNumeric(const string &group);
int makeUidNumeric(const string &user);
void cleanSlashes(string &str);

/** The DTime class can be used for timing statistics with microsecond resolution. 
On 32 bits systems this means that 2147 seconds is the longest time that can be measured. */
class DTime 
{
public:
  DTime(); //!< Does not set the timer for you! Saves lots of gettimeofday() calls
  DTime(const DTime &dt);
  time_t time();
  inline void set();  //!< Reset the timer
  inline int udiff(); //!< Return the number of microseconds since the timer was last set.
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
const string sockAddrToString(struct sockaddr_in *remote);
int sendData(const char *buffer, int replen, int outsock);

inline void DTime::set()
{
  Utility::gettimeofday(&d_set,0);
}

inline int DTime::udiff()
{
  struct timeval now;

  Utility::gettimeofday(&now,0);
  int ret=1000000*(now.tv_sec-d_set.tv_sec)+(now.tv_usec-d_set.tv_usec);
  d_set=now;
  return ret;
}

inline bool dns_isspace(char c)
{
  return c==' ' || c=='\t' || c=='\r' || c=='\n';
}

inline char dns_tolower(char c)
{
  if(c>='A' && c<='Z')
    c+='a'-'A';
  return c;
}

inline const string toLower(const string &upper)
{
  string reply(upper);
  char c;
  for(unsigned int i = 0; i < reply.length(); i++) {
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
    char c;
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
        	r[i] = toupper( r[i] );
        }
        return r;
}

inline double getTime()
{
  struct timeval now;
  Utility::gettimeofday(&now,0);
  
  return now.tv_sec+now.tv_usec/1000000.0;
}

inline void unixDie(const string &why)
{
  throw runtime_error(why+": "+strerror(errno));
}

string makeHexDump(const string& str);
void shuffle(vector<DNSResourceRecord>& rrs);

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

inline bool pdns_ilexicographical_compare(const std::string& a, const std::string& b)  __attribute__((pure));
inline bool pdns_ilexicographical_compare(const std::string& a, const std::string& b) 
{
  string::size_type aLen = a.length(), bLen = b.length(), n;
  const unsigned char *aPtr = (const unsigned char*)a.c_str(), *bPtr = (const unsigned char*)b.c_str();
  int result;
  
  for(n = 0 ; n < aLen && n < bLen ; ++n) {
      if((result = dns_tolower(*aPtr++) - dns_tolower(*bPtr++))) {
        return result < 0;
      }
  }
  if(n == aLen && n == bLen) // strings are equal (in length)
    return 0; 
  if(n == aLen) // first string was shorter
    return true; 
  return false;
}

inline bool pdns_iequals(const std::string& a, const std::string& b) __attribute__((pure));

inline bool pdns_iequals(const std::string& a, const std::string& b) 
{
  string::size_type aLen = a.length(), bLen = b.length(), n;
  const char *aPtr = a.c_str(), *bPtr = b.c_str();
  
  for(n = 0 ; n < aLen && n < bLen ; ++n) {
      if(dns_tolower(*aPtr++) != dns_tolower(*bPtr++))
        return false;
  }
  return aLen == bLen; // strings are equal (in length)
}

// lifted from boost, with thanks
class AtomicCounter
{
public:

    explicit AtomicCounter( unsigned int v = 0) : value_( v ) {}

    unsigned int operator++()
    {
      return atomic_exchange_and_add( &value_, +1 ) + 1;
    }

    unsigned int operator--()
    {
      return atomic_exchange_and_add( &value_, -1 ) - 1;
    }

    operator unsigned int() const
    {
      return atomic_exchange_and_add( &value_, 0);
    }

private:
    AtomicCounter(AtomicCounter const &);
    AtomicCounter &operator=(AtomicCounter const &);

    mutable unsigned int value_;
    
    // the below is necessary because __sync_fetch_and_add is not universally available on i386.. I 3> RHEL5. 
    #if defined( __GNUC__ ) && ( defined( __i386__ ) || defined( __x86_64__ ) )
    static int atomic_exchange_and_add( unsigned int * pw, int dv )
    {
        // int r = *pw;
        // *pw += dv;
        // return r;

        int r;

        __asm__ __volatile__
        (
            "lock\n\t"
            "xadd %1, %0":
            "+m"( *pw ), "=r"( r ): // outputs (%0, %1)
            "1"( dv ): // inputs (%2 == %1)
            "memory", "cc" // clobbers
        );

        return r;
    }
    #else 
    static int atomic_exchange_and_add( unsigned int * pw, int dv )
    {
      return __sync_fetch_and_add(pw, dv);
    }
    #endif
};


struct CIStringCompare: public binary_function<string, string, bool>  
{
  bool operator()(const string& a, const string& b) const
  {
    return pdns_ilexicographical_compare(a, b);
  }
};

pair<string, string> splitField(const string& inp, char sepa);

inline bool isCanonical(const string& dom)
{
  if(dom.empty())
    return false;
  return dom[dom.size()-1]=='.';
}

inline string toCanonic(const string& zone, const string& domain)
{
  if(domain.length()==1 && domain[0]=='@')
    return zone;

  if(isCanonical(domain))
    return domain;
  string ret=domain;
  ret.append(1,'.');
  if(!zone.empty() && zone[0]!='.')
    ret.append(zone);
  return ret;
}

inline void setSocketReusable(int fd)
{
  int tmp=1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, static_cast<unsigned>(sizeof tmp));
}

string stripDot(const string& dom);
void seedRandom(const string& source);
string makeRelative(const std::string& fqdn, const std::string& zone);
string labelReverse(const std::string& qname);
std::string dotConcat(const std::string& a, const std::string &b);
int makeIPv6sockaddr(const std::string& addr, struct sockaddr_in6* ret);
bool stringfgets(FILE* fp, std::string& line);
#endif
