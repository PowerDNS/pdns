#ifndef XGDBM_HH
#define XGDBM_HH

#include "xdb.hh"
#include <gdbm.h>

class XGDBMWrapper : public XDBWrapper
{
public:
  XGDBMWrapper(const string &filename, Mode mode=ReadOnly);
  ~XGDBMWrapper();
  bool get(const string &key, string &value);
  void del(const string &key);
  void put(const string &key, const string &value);
private:
  static GDBM_FILE s_db;
  static int s_usecount;
};
#endif
