#pragma once
#include "namespaces.hh"
#include <boost/variant/variant.hpp>
#include <utility>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "ext/luawrapper/include/LuaContext.hpp"

class BaseLua4 : public boost::noncopyable
{
protected:
  std::unique_ptr<LuaContext> d_lw; // this is way on top because it must get destroyed _last_
  std::string d_include_path; // path where scripts to include at postLoad are

public:
  BaseLua4(std::string includePath) :
    d_include_path(std::move(includePath)) {};
  void loadFile(const std::string &fname, bool doPostLoad=true);
  void loadString(const std::string &script);
  void loadStream(std::istream &stream, bool doPostLoad=true);
  void includePath(const std::string &directory);
  virtual ~BaseLua4(); // this is so unique_ptr works with an incomplete type
protected:
  void prepareContext();
  virtual void postPrepareContext() = 0;
  virtual void postLoad() = 0;
  typedef vector<pair<string, int>> in_t;
  vector<pair<string, boost::variant<int, in_t, struct timeval*>>> d_pd;
  typedef vector<pair<string, boost::variant<string, bool, int, double>>> Features;
  virtual void getFeatures(Features&);
};
