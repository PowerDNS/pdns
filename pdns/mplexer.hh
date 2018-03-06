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
#include <vector>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/time.h>

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
protected:

  typedef boost::function< void(int, funcparam_t&) > callbackfunc_t;
  struct Callback
  {
    callbackfunc_t d_callback;
    funcparam_t d_parameter;
    struct timeval d_ttd;
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
  virtual void addReadFD(int fd, callbackfunc_t toDo, const funcparam_t& parameter=funcparam_t())
  {
    this->addFD(d_readCallbacks, fd, toDo, parameter);
  }

  //! Add an fd to the write watch list - currently an fd can only be on one list at a time!
  virtual void addWriteFD(int fd, callbackfunc_t toDo, const funcparam_t& parameter=funcparam_t())
  {
    this->addFD(d_writeCallbacks, fd, toDo, parameter);
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
    if(!d_readCallbacks.count(fd))
      throw FDMultiplexerException("attempt to timestamp fd not in the multiplexer");
    tv.tv_sec += timeout;
    d_readCallbacks[fd].d_ttd=tv;
  }

  virtual funcparam_t& getReadParameter(int fd) 
  {
    if(!d_readCallbacks.count(fd))
      throw FDMultiplexerException("attempt to look up data in multiplexer for unlisted fd "+std::to_string(fd));
    return d_readCallbacks[fd].d_parameter;
  }

  virtual std::vector<std::pair<int, funcparam_t> > getTimeouts(const struct timeval& tv)
  {
    std::vector<std::pair<int, funcparam_t> > ret;
    for(callbackmap_t::iterator i=d_readCallbacks.begin(); i!=d_readCallbacks.end(); ++i)
      if(i->second.d_ttd.tv_sec && boost::tie(tv.tv_sec, tv.tv_usec) > boost::tie(i->second.d_ttd.tv_sec, i->second.d_ttd.tv_usec)) 
        ret.push_back(std::make_pair(i->first, i->second.d_parameter));
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

protected:
  typedef std::map<int, Callback> callbackmap_t;
  callbackmap_t d_readCallbacks, d_writeCallbacks;

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter)=0;
  virtual void removeFD(callbackmap_t& cbmap, int fd)=0;
  bool d_inrun;
  callbackmap_t::iterator d_iter;

  void accountingAddFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter)
  {
    Callback cb;
    cb.d_callback=toDo;
    cb.d_parameter=parameter;
    memset(&cb.d_ttd, 0, sizeof(cb.d_ttd));
  
    if(cbmap.count(fd))
      throw FDMultiplexerException("Tried to add fd "+std::to_string(fd)+ " to multiplexer twice");
    cbmap[fd]=cb;
  }

  void accountingRemoveFD(callbackmap_t& cbmap, int fd) 
  {
    if(!cbmap.erase(fd)) 
      throw FDMultiplexerException("Tried to remove unlisted fd "+std::to_string(fd)+ " from multiplexer");
  }
};


#endif

