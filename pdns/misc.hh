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
#include <cinttypes>
#include <cstring>
#include <cstdio>
#include <regex.h>
#include <climits>
#include <type_traits>

#include <boost/algorithm/string.hpp>

#include "dns.hh"
#include <atomic>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ctime>
#include <syslog.h>
#include <stdexcept>
#include <string>
#include <cctype>
#include <utility>
#include <vector>

#include "namespaces.hh"

class DNSName;

// Do not change to "using TSIGHashEnum ..." until you know CodeQL does not choke on it
typedef enum
{
  TSIG_MD5,
  TSIG_SHA1,
  TSIG_SHA224,
  TSIG_SHA256,
  TSIG_SHA384,
  TSIG_SHA512,
  TSIG_GSS,
} TSIGHashEnum;

namespace pdns
{
/**
 * \brief Retrieves the errno-based error message in a reentrant way.
 *
 * This internally handles the portability issues around using
 * `strerror_r` and returns a `std::string` that owns the error
 * message's contents.
 *
 * \param[in] errnum The errno value.
 *
 * \return The `std::string` error message.
 */
auto getMessageFromErrno(int errnum) -> std::string;

#if defined(HAVE_LIBCRYPTO)
namespace OpenSSL
{
  /**
   * \brief Throws a `std::runtime_error` with the current OpenSSL error.
   *
   * \param[in] errorMessage The message to attach in addition to the OpenSSL error.
   */
  [[nodiscard]] auto error(const std::string& errorMessage) -> std::runtime_error;

  /**
   * \brief Throws a `std::runtime_error` with a name and the current OpenSSL error.
   *
   * \param[in] componentName The name of the component to mark the error message with.
   * \param[in] errorMessage The message to attach in addition to the OpenSSL error.
   */
  [[nodiscard]] auto error(const std::string& componentName, const std::string& errorMessage) -> std::runtime_error;
}
#endif // HAVE_LIBCRYPTO
}

string nowTime();
string unquotify(const string &item);
string humanDuration(time_t passed);
bool stripDomainSuffix(string *qname, const string &domain);
void stripLine(string &line);
std::optional<string> getHostname();
std::string getCarbonHostName();
string urlEncode(const string &text);
int waitForData(int fileDesc, int seconds, int useconds = 0);
int waitFor2Data(int fd1, int fd2, int seconds, int useconds, int* fd);
int waitForMultiData(const set<int>& fds, const int seconds, const int useconds, int* fd);
int waitForRWData(int fileDesc, bool waitForRead, int seconds, int useconds, bool* error = nullptr, bool* disconnected = nullptr);
bool getTSIGHashEnum(const DNSName& algoName, TSIGHashEnum& algoEnum);
DNSName getTSIGAlgoName(TSIGHashEnum& algoEnum);

int logFacilityToLOG(unsigned int facility);
std::optional<int> logFacilityFromString(std::string facilityStr);

template<typename Container>
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
  static_assert(std::is_unsigned_v<T>, "rfc1982LessThan only works for unsigned types");
  return std::make_signed_t<T>(a - b) < 0;
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
      container.emplace_back(i, len);
      return;
    } else
      container.emplace_back(i, j);

    // set up for next loop
    i = j + 1;
  }
}

size_t writen2(int fd, const void *buf, size_t count);
inline size_t writen2(int fd, const std::string &s) { return writen2(fd, s.data(), s.size()); }
size_t readn2(int fileDesc, void* buffer, size_t len);
size_t readn2WithTimeout(int fd, void* buffer, size_t len, const struct timeval& idleTimeout, const struct timeval& totalTimeout={0,0}, bool allowIncomplete=false);
size_t writen2WithTimeout(int fd, const void * buffer, size_t len, const struct timeval& timeout);

void toLowerInPlace(string& str);
const string toLower(const string &upper);
const string toLowerCanonic(const string &upper);
bool IpToU32(const string &str, uint32_t *ip);
string U32ToIP(uint32_t);

inline string stringerror(int err = errno)
{
  return pdns::getMessageFromErrno(err);
}

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
  //!< Does not set the timer for you! Saves lots of gettimeofday() calls
  DTime() = default;
  DTime(const DTime &dt) = default;
  DTime & operator=(const DTime &dt) = default;
  inline time_t time() const;
  inline void set();  //!< Reset the timer
  inline int udiff(bool reset = true); //!< Return the number of microseconds since the timer was last set.

  int udiffNoReset() //!< Return the number of microseconds since the timer was last set.
  {
    return udiff(false);
  }
  void setTimeval(const struct timeval& tv)
  {
    d_set=tv;
  }
  struct timeval getTimeval() const
  {
    return d_set;
  }
private:
struct timeval d_set{0, 0};
};

inline time_t DTime::time() const
{
  return d_set.tv_sec;
}

inline void DTime::set()
{
  gettimeofday(&d_set, nullptr);
}

inline int DTime::udiff(bool reset)
{
  struct timeval now;
  gettimeofday(&now, nullptr);

  int ret=1000000*(now.tv_sec-d_set.tv_sec)+(now.tv_usec-d_set.tv_usec);

  if (reset) {
    d_set = now;
  }

  return ret;
}

inline void toLowerInPlace(string& str)
{
  const size_t length = str.length();
  char c;
  for (size_t i = 0; i < length; ++i) {
    c = dns_tolower(str[i]);
    if (c != str[i]) {
      str[i] = c;
    }
  }
}

inline const string toLower(const string &upper)
{
  string reply(upper);

  toLowerInPlace(reply);

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

[[noreturn]] inline void unixDie(const string &why)
{
  throw runtime_error(why + ": " + stringerror(errno));
}

string makeHexDump(const string& str, const string& sep = " ");
//! Convert the hexstring in to a byte string
string makeBytesFromHex(const string &in);

void normalizeTV(struct timeval& tv);
struct timeval operator+(const struct timeval& lhs, const struct timeval& rhs);
struct timeval operator-(const struct timeval& lhs, const struct timeval& rhs);

inline float makeFloat(const struct timeval& tv)
{
  return tv.tv_sec + tv.tv_usec/1000000.0f;
}
inline uint64_t uSec(const struct timeval& tv)
{
  return tv.tv_sec * 1000000 + tv.tv_usec;
}

inline bool operator<(const struct timeval& lhs, const struct timeval& rhs)
{
  return std::tie(lhs.tv_sec, lhs.tv_usec) < std::tie(rhs.tv_sec, rhs.tv_usec);
}
inline bool operator<=(const struct timeval& lhs, const struct timeval& rhs)
{
  return std::tie(lhs.tv_sec, lhs.tv_usec) <= std::tie(rhs.tv_sec, rhs.tv_usec);
}

inline bool operator<(const struct timespec& lhs, const struct timespec& rhs)
{
  return std::tie(lhs.tv_sec, lhs.tv_nsec) < std::tie(rhs.tv_sec, rhs.tv_nsec);
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
struct CIStringCompare
{
  bool operator()(const string& a, const string& b) const
  {
    return pdns_ilexicographical_compare(a, b);
  }
};

struct CIStringComparePOSIX
{
   bool operator() (const std::string& lhs, const std::string& rhs) const
   {
      const std::locale &loc = std::locale("POSIX");
      auto lhsIter = lhs.begin();
      auto rhsIter = rhs.begin();
      while (lhsIter != lhs.end()) {
        if (rhsIter == rhs.end() || std::tolower(*rhsIter,loc) < std::tolower(*lhsIter,loc)) {
          return false;
        }
        if (std::tolower(*lhsIter,loc) < std::tolower(*rhsIter,loc)) {
          return true;
        }
        ++lhsIter;++rhsIter;
      }
      return rhsIter != rhs.end();
   }
};

struct CIStringPairCompare
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
  SimpleMatch(string mask, bool caseFold = false) :
    d_mask(std::move(mask)), d_fold(caseFold)
  {
  }

  bool match(string::const_iterator mi, string::const_iterator mend, string::const_iterator vi, string::const_iterator vend) const
  {
    for(;;++mi) {
      if (mi == mend) {
        return vi == vend;
      } else if (*mi == '?') {
        if (vi == vend) return false;
        ++vi;
      } else if (*mi == '*') {
        while(mi != mend && *mi == '*') ++mi;
        if (mi == mend) return true;
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

  bool match(const string& value) const {
    return match(d_mask.begin(), d_mask.end(), value.begin(), value.end());
  }

  bool match(const DNSName& name) const {
    return match(name.toStringNoDot());
  }

private:
  const string d_mask;
  const bool d_fold;
};

union ComboAddress;

// An aligned type to hold cmsgbufs. See https://man.openbsd.org/CMSG_DATA
typedef union { struct cmsghdr hdr; char buf[256]; } cmsgbuf_aligned;

/* itfIndex is an interface index, as returned by if_nametoindex(). 0 means default. */
void addCMsgSrcAddr(struct msghdr* msgh, cmsgbuf_aligned* cbuf, const ComboAddress* source, int itfIndex);

unsigned int getFilenumLimit(bool hardOrSoft=0);
void setFilenumLimit(unsigned int lim);
bool readFileIfThere(const char* fname, std::string* line);
bool setSocketTimestamps(int fd);

//! Sets the socket into blocking mode.
bool setBlocking( int sock );

//! Sets the socket into non-blocking mode.
bool setNonBlocking( int sock );
bool setTCPNoDelay(int sock);
bool setReuseAddr(int sock);
bool isNonBlocking(int sock);
bool setReceiveSocketErrors(int sock, int af);
int closesocket(int socket);
bool setCloseOnExec(int sock);

size_t getPipeBufferSize(int fd);
bool setPipeBufferSize(int fd, size_t size);

uint64_t udpErrorStats(const std::string& str);
uint64_t udp6ErrorStats(const std::string& str);
uint64_t tcpErrorStats(const std::string& str);
uint64_t getRealMemoryUsage(const std::string&);
uint64_t getSpecialMemoryUsage(const std::string&);
uint64_t getOpenFileDescriptors(const std::string&);
uint64_t getCPUTimeUser(const std::string&);
uint64_t getCPUTimeSystem(const std::string&);
uint64_t getCPUIOWait(const std::string&);
uint64_t getCPUSteal(const std::string&);
std::string getMACAddress(const ComboAddress& ca);
int getMACAddress(const ComboAddress& ca, char* dest, size_t len);

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
template <typename Integer,
typename std::enable_if_t<std::is_integral_v<Integer>, bool> = true>
const char* addS(Integer siz, const char* singular = "", const char *plural = "s")
{
  if (siz == 1) {
    return singular;
  }
  return plural;
}

template <typename C,
typename std::enable_if_t<std::is_class_v<C>, bool> = true>
const char* addS(const C& c, const char* singular = "", const char *plural = "s")
{
  return addS(c.size(), singular, plural);
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

namespace pdns
{
/**
 * \brief Does a checked conversion from one integer type to another.
 *
 * \warning The source type `F` and target type `T` must have the same
 * signedness, otherwise a compilation error is thrown.
 *
 * \exception std::out_of_range Thrown if the source value does not fit
 * in the target type.
 *
 * \param[in] from The source value of type `F`.
 *
 * \return The target value of type `T`.
 */
template <typename T, typename F>
auto checked_conv(F from) -> T
{
  static_assert(std::numeric_limits<F>::is_integer, "checked_conv: The `F` type must be an integer");
  static_assert(std::numeric_limits<T>::is_integer, "checked_conv: The `T` type must be an integer");
  static_assert((std::numeric_limits<F>::is_signed && std::numeric_limits<T>::is_signed) || (!std::numeric_limits<F>::is_signed && !std::numeric_limits<T>::is_signed),
                "checked_conv: The `T` and `F` types must either both be signed or unsigned");

  constexpr auto tMin = std::numeric_limits<T>::min();
  if constexpr (std::numeric_limits<F>::min() != tMin) {
    if (from < tMin) {
      string s = "checked_conv: source value " + std::to_string(from) + " is smaller than target's minimum possible value " + std::to_string(tMin);
      throw std::out_of_range(s);
    }
  }

  constexpr auto tMax = std::numeric_limits<T>::max();
  if constexpr (std::numeric_limits<F>::max() != tMax) {
    if (from > tMax) {
      string s = "checked_conv: source value " + std::to_string(from) + " is larger than target's maximum possible value " + std::to_string(tMax);
      throw std::out_of_range(s);
    }
  }

  return static_cast<T>(from);
}

/**
 * \brief Performs a conversion from `std::string&` to integer.
 *
 * This function internally calls `std::stoll` and `std::stoull` to do
 * the conversion from `std::string&` and calls `pdns::checked_conv` to
 * do the checked conversion from `long long`/`unsigned long long` to
 * `T`.
 *
 * \warning The target type `T` must be an integer, otherwise a
 * compilation error is thrown.
 *
 * \exception std:stoll Throws what std::stoll throws.
 *
 * \exception std::stoull Throws what std::stoull throws.
 *
 * \exception pdns::checked_conv Throws what pdns::checked_conv throws.
 *
 * \param[in] str The input string to be converted.
 *
 * \param[in] idx Location to store the index at which processing
 * stopped. If the input `str` is empty, `*idx` shall be set to 0.
 *
 * \param[in] base The numerical base for conversion.
 *
 * \return `str` converted to integer `T`, or 0 if `str` is empty.
 */
template <typename T>
auto checked_stoi(const std::string& str, size_t* idx = nullptr, int base = 10) -> T
{
  static_assert(std::numeric_limits<T>::is_integer, "checked_stoi: The `T` type must be an integer");

  if (str.empty()) {
    if (idx != nullptr) {
      *idx = 0;
    }

    return 0; // compatibility
  }

  if constexpr (std::is_unsigned_v<T>) {
    return pdns::checked_conv<T>(std::stoull(str, idx, base));
  }
  else {
    return pdns::checked_conv<T>(std::stoll(str, idx, base));
  }
}

/**
 * \brief Performs a conversion from `std::string&` to integer.
 *
 * This function internally calls `pdns::checked_stoi` and stores its
 * result in `out`.
 *
 * \exception pdns::checked_stoi Throws what pdns::checked_stoi throws.
 *
 * \param[out] out `str` converted to integer `T`, or 0 if `str` is
 * empty.
 *
 * \param[in] str The input string to be converted.
 *
 * \param[in] idx Location to store the index at which processing
 * stopped. If the input `str` is empty, `*idx` shall be set to 0.
 *
 * \param[in] base The numerical base for conversion.
 *
 * \return `str` converted to integer `T`, or 0 if `str` is empty.
 */
template <typename T>
auto checked_stoi_into(T& out, const std::string& str, size_t* idx = nullptr, int base = 10)
{
  out = checked_stoi<T>(str, idx, base);
}
}

bool isSettingThreadCPUAffinitySupported();
int mapThreadToCPUList(pthread_t tid, const std::set<int>& cpus);

std::vector<ComboAddress> getResolvers(const std::string& resolvConfPath);

DNSName reverseNameFromIP(const ComboAddress& ip);

size_t parseRFC1035CharString(const std::string &in, std::string &val); // from ragel
size_t parseSVCBValueListFromParsedRFC1035CharString(const std::string &in, vector<std::string> &val); // from ragel
size_t parseSVCBValueList(const std::string &in, vector<std::string> &val);

std::string makeLuaString(const std::string& in);

bool constantTimeStringEquals(const std::string& a, const std::string& b);

// Used in NID and L64 records
struct NodeOrLocatorID { uint8_t content[8]; };

struct FDWrapper
{
  FDWrapper() = default;
  FDWrapper(int desc): d_fd(desc) {}
  FDWrapper(const FDWrapper&) = delete;
  FDWrapper& operator=(const FDWrapper& rhs) = delete;


  ~FDWrapper()
  {
    reset();
  }

  FDWrapper(FDWrapper&& rhs) noexcept : d_fd(rhs.d_fd)
  {
    rhs.d_fd = -1;
  }

  FDWrapper& operator=(FDWrapper&& rhs) noexcept
  {
    if (d_fd >= 0) {
      close(d_fd);
    }
    d_fd = rhs.d_fd;
    rhs.d_fd = -1;
    return *this;
  }

  [[nodiscard]] int getHandle() const
  {
    return d_fd;
  }

  operator int() const
  {
    return d_fd;
  }

  int reset()
  {
    int ret = 0;
    if (d_fd >= 0) {
      ret = close(d_fd);
    }
    d_fd = -1;
    return ret;
  }

private:
  int d_fd{-1};
};

namespace pdns
{
[[nodiscard]] std::optional<std::string> visit_directory(const std::string& directory, const std::function<bool(ino_t inodeNumber, const std::string_view& name)>& visitor);

struct FilePtrDeleter
{
  /* using a deleter instead of decltype(&fclose) has two big advantages:
     - the deleter is included in the type and does not have to be passed
       when creating a new object (easier to use, less memory usage, in theory
       better inlining)
     - we avoid the annoying "ignoring attributes on template argument ‘int (*)(FILE*)’"
       warning from the compiler, which is there because fclose is tagged as __nonnull((1))
  */
  void operator()(FILE* filePtr) const noexcept {
    fclose(filePtr);
  }
};

using UniqueFilePtr = std::unique_ptr<FILE, FilePtrDeleter>;

UniqueFilePtr openFileForWriting(const std::string& filePath, mode_t permissions, bool mustNotExist = true, bool appendIfExists = false);
}
