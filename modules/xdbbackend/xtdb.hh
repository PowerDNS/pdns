#include "xdb.hh"
#include <pthread.h>
#include <tdb.h>

class XTDBWrapper : public XDBWrapper
{
public:
  XTDBWrapper(const string &filename);
  ~XTDBWrapper();
  bool get(const string &key, string &value);
  void del(const string &key);
  void put(const string &key, const string &value);
private:
  static TDB_CONTEXT *s_db;
  static int s_usecount;
  static pthread_mutex_t s_lock;
};
