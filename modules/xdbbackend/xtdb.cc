#include "xtdb.hh"
#include "pdns/lock.hh"
#include <tdb.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>


#include "pdns/namespaces.hh"

TDB_CONTEXT *XTDBWrapper::s_db;
int XTDBWrapper::s_usecount;
pthread_mutex_t XTDBWrapper::s_lock=PTHREAD_MUTEX_INITIALIZER;

XTDBWrapper::XTDBWrapper(const string &fname)
{
  Lock l(&s_lock);
  if(!s_db) {
    s_db = tdb_open(const_cast<char *>(fname.c_str()), 5213331,
        	  TDB_NOLOCK,
        	  O_RDWR | O_CREAT , 0600);
    if(!s_db)
      throw XDBException("Unable to open database: "+string(strerror(errno)));
  }
  s_usecount++;

}

XTDBWrapper::~XTDBWrapper()
{
  if(!--s_usecount) {
    tdb_close(s_db);
    cerr<<"closed"<<endl;
  }
}

bool XTDBWrapper::get(const string &key, string &value)
{

  TDB_DATA kdatum={const_cast<char *>(key.c_str()),key.size()+1};
  TDB_DATA vdatum;

  {
    //Lock l(&s_lock);
    vdatum=tdb_fetch(s_db,kdatum);
  }
  if(!vdatum.dptr)
    return false;
  value.assign(vdatum.dptr,vdatum.dsize);
  free(vdatum.dptr);
  return true;
}

void XTDBWrapper::put(const string &key, const string &value)
{
  TDB_DATA kdatum={const_cast<char *>(key.c_str()),key.size()+1};
  TDB_DATA vdatum={const_cast<char *>(value.c_str()),value.size()};
  if(tdb_store(s_db, kdatum, vdatum,TDB_REPLACE)<0)
    throw XDBException("Error storing key: "+string(strerror(errno)));

}

void XTDBWrapper::del(const string &key)
{
}

#ifdef TESTDRIVER
main()
{
  XDBWrapper *xdb=new XTDBWrapper("wuh");
  xdb->put("ahu","toffe gast");
  xdb->append("ahu",", echt waar!");

  string tst;
  xdb->get("ahu",tst);
  cout<<"Database zegt over ahu: '"<<tst<<"'"<<endl;

  xdb->append("ahu"," Toch niet!");
  xdb->get("ahu",tst);
  cout<<"Database zegt over ahu: '"<<tst<<"'"<<endl;

}
#endif
