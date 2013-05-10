#ifndef XDB_HH
#define XDB_HH
#include <string>
using std::string;

class XDBException
{
public:
  XDBException(const string &ex) : what(ex){}
  string what;
};

class XDBWrapper
{
public:
  virtual ~XDBWrapper(){}
  virtual bool get(const string &key, string &value)=0;
  virtual void del(const string &key)=0;
  virtual void put(const string &key, const string &value)=0;
  virtual void append(const string &key, const string &value)
  {
    string newKey;
    get(key,newKey);
    put(key,newKey+value);
  }
  typedef enum {ReadOnly, ReadWrite} Mode;
};

#endif
