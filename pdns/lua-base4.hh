#pragma once
#include "namespaces.hh"
#include <boost/variant/variant.hpp>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

class LuaContext;

#if defined(HAVE_LUA)
#undef L
#include "ext/luawrapper/include/LuaContext.hpp"
#define L theL()
#endif

class BaseLua4 : public boost::noncopyable
{
protected:
#ifdef HAVE_LUA
  std::unique_ptr<LuaContext> d_lw; // this is way on top because it must get destroyed _last_
#endif

public:
  explicit BaseLua4(const std::string &fname);

  virtual ~BaseLua4(); // this is so unique_ptr works with an incomplete type
protected:
  void prepareContext();
  virtual void postPrepareContext() = 0;
  virtual void postLoad() = 0;
  typedef vector<pair<string, int> > in_t;
  vector<pair<string, boost::variant<int, in_t, struct timeval* > > > d_pd;
};
