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
#ifndef PDNS_MPLEXER_HH
#define PDNS_MPLEXER_HH
#include <boost/function.hpp>
#include <boost/any.hpp>
#include <boost/shared_array.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <vector>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/time.h>

using namespace ::boost::multi_index;

class FDMultiplexerException : public std::runtime_error
{
public:
  FDMultiplexerException(const std::string& str) : std::runtime_error(str)
  {}
};


/** Very simple FD multiplexer, based on callbacks and boost::any parameters
    As a special service, this parameter is kept around and can be modified, 
    allowing for state to be stored inside the multiplexer.

    It has some "interesting" semantics
*/

class FDMultiplexer
{
public:
  typedef boost::any funcparam_t;
  typedef boost::function< void(int, funcparam_t&) > callbackfunc_t;
protected:

  struct Callback
  {
    callbackfunc_t d_callback;
    mutable funcparam_t d_parameter;
    struct timeval d_ttd;
    int d_fd;
  };

public:
  FDMultiplexer() : d_inrun(false)
  {}
  virtual ~FDMultiplexer()
  {}

  static FDMultiplexer* getMultiplexerSilent();
  
  /* tv will be updated to 'now' before run returns */
  /* timeout is in ms */
  virtual int run(struct timeval* tv, int timeout=500) = 0;

  /* timeout is in ms, 0 will return immediatly, -1 will block until at least one FD is ready */
  virtual void getAvailableFDs(std::vector<int>& fds, int timeout) = 0;

  //! Add an fd to the read watch list - currently an fd can only be on one list at a time!
  virtual void addReadFD(int fd, callbackfunc_t toDo, const funcparam_t& parameter=funcparam_t(), const struct timeval* ttd=nullptr)
  {
    this->addFD(d_readCallbacks, fd, toDo, parameter, ttd);
  }

  //! Add an fd to the write watch list - currently an fd can only be on one list at a time!
  virtual void addWriteFD(int fd, callbackfunc_t toDo, const funcparam_t& parameter=funcparam_t(), const struct timeval* ttd=nullptr)
  {
    this->addFD(d_writeCallbacks, fd, toDo, parameter, ttd);
  }

  //! Remove an fd from the read watch list. You can't call this function on an fd that is closed already!
  /** WARNING: references to 'parameter' become invalid after this function! */
  virtual void removeReadFD(int fd)
  {
    this->removeFD(d_readCallbacks, fd);
  }

  //! Remove an fd from the write watch list. You can't call this function on an fd that is closed already!
  /** WARNING: references to 'parameter' become invalid after this function! */
  virtual void removeWriteFD(int fd)
  {
    this->removeFD(d_writeCallbacks, fd);
  }

  virtual void setReadTTD(int fd, struct timeval tv, int timeout)
  {
    const auto& it = d_readCallbacks.find(fd);
    if (it == d_readCallbacks.end()) {
      throw FDMultiplexerException("attempt to timestamp fd not in the multiplexer");
    }

    auto newEntry = *it;
    tv.tv_sec += timeout;
    newEntry.d_ttd = tv;
    d_readCallbacks.replace(it, newEntry);
  }

  virtual void setWriteTTD(int fd, struct timeval tv, int timeout)
  {
    const auto& it = d_writeCallbacks.find(fd);
    if (it == d_writeCallbacks.end()) {
      throw FDMultiplexerException("attempt to timestamp fd not in the multiplexer");
    }

    auto newEntry = *it;
    tv.tv_sec += timeout;
    newEntry.d_ttd = tv;
    d_writeCallbacks.replace(it, newEntry);
  }

  virtual std::vector<std::pair<int, funcparam_t> > getTimeouts(const struct timeval& tv, bool writes=false)
  {
    std::vector<std::pair<int, funcparam_t> > ret;
    const auto tied = boost::tie(tv.tv_sec, tv.tv_usec);
    auto& idx = writes ? d_writeCallbacks.get<TTDOrderedTag>() : d_readCallbacks.get<TTDOrderedTag>();

    for (auto it = idx.begin(); it != idx.end(); ++it) {
      if (it->d_ttd.tv_sec == 0 || tied <= boost::tie(it->d_ttd.tv_sec, it->d_ttd.tv_usec)) {
        break;
      }
      ret.push_back(std::make_pair(it->d_fd, it->d_parameter));
    }

    return ret;
  }

  typedef FDMultiplexer* getMultiplexer_t();
  typedef std::multimap<int, getMultiplexer_t*> FDMultiplexermap_t;

  static FDMultiplexermap_t& getMultiplexerMap()
  {
    static FDMultiplexermap_t theMap;
    return theMap;
  }
  
  virtual std::string getName() const = 0;

  size_t getWatchedFDCount(bool writeFDs) const
  {
    return writeFDs ? d_writeCallbacks.size() : d_readCallbacks.size();
  }

protected:
  struct FDBasedTag {};
  struct TTDOrderedTag {};
  struct ttd_compare
  {
    /* we want a 0 TTD (no timeout) to come _after_ everything else */
    bool operator() (const struct timeval& lhs, const struct timeval& rhs) const
    {
      /* special treatment if at least one of the TTD is 0,
         normal comparison otherwise */
      if (lhs.tv_sec == 0 && rhs.tv_sec == 0) {
        return false;
      }
      if (lhs.tv_sec == 0 && rhs.tv_sec != 0) {
        return false;
      }
      if (lhs.tv_sec != 0 && rhs.tv_sec == 0) {
        return true;
      }

      return std::tie(lhs.tv_sec, lhs.tv_usec) < std::tie(rhs.tv_sec, rhs.tv_usec);
    }
  };

  typedef multi_index_container<
    Callback,
    indexed_by <
                hashed_unique<tag<FDBasedTag>,
                              member<Callback,int,&Callback::d_fd>
                              >,
                ordered_non_unique<tag<TTDOrderedTag>,
                                   member<Callback,struct timeval,&Callback::d_ttd>,
                                   ttd_compare
                                   >
               >
  > callbackmap_t;

  callbackmap_t d_readCallbacks, d_writeCallbacks;

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd=nullptr)=0;
  virtual void removeFD(callbackmap_t& cbmap, int fd)=0;
  bool d_inrun;
  callbackmap_t::iterator d_iter;

  void accountingAddFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd=nullptr)
  {
    Callback cb;
    cb.d_fd = fd;
    cb.d_callback=toDo;
    cb.d_parameter=parameter;
    memset(&cb.d_ttd, 0, sizeof(cb.d_ttd));
    if (ttd) {
      cb.d_ttd = *ttd;
    }

    auto pair = cbmap.insert(cb);
    if (!pair.second) {
      throw FDMultiplexerException("Tried to add fd "+std::to_string(fd)+ " to multiplexer twice");
    }
  }

  void accountingRemoveFD(callbackmap_t& cbmap, int fd) 
  {
    if(!cbmap.erase(fd)) {
      throw FDMultiplexerException("Tried to remove unlisted fd "+std::to_string(fd)+ " from multiplexer");
    }
  }
};


#endif

