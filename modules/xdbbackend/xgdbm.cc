#include "xgdbm.hh"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>

using namespace std;

GDBM_FILE XGDBMWrapper::s_db;
int XGDBMWrapper::s_usecount;

XGDBMWrapper::XGDBMWrapper(const string &fname, Mode mode)
{
  if(!s_db) {
    s_db = gdbm_open(const_cast<char *>(fname.c_str()), 2048,
        	  mode==ReadWrite ? GDBM_WRITER|GDBM_WRCREAT|GDBM_FAST : GDBM_READER,
        	  0666 , 0); 
    if(!s_db) 
      throw XDBException("Unable to open database: "+string(strerror(errno)));
  }
  s_usecount++;
}

XGDBMWrapper::~XGDBMWrapper()
{
  if(!--s_usecount) {
    cerr<<"Closing down"<<endl;
    gdbm_close(s_db);
  }
}

bool XGDBMWrapper::get(const string &key, string &value)
{
  datum kdatum={const_cast<char *>(key.c_str()),key.size()+1};
  
  datum vdatum=gdbm_fetch(s_db,kdatum);
  if(!vdatum.dptr)
    return false;
  value.assign(vdatum.dptr,vdatum.dsize);
  free(vdatum.dptr);
  return true;
}

void XGDBMWrapper::put(const string &key, const string &value)
{
  datum kdatum={const_cast<char *>(key.c_str()),key.size()+1};
  datum vdatum={const_cast<char *>(value.c_str()),value.size()};
  if(gdbm_store(s_db, kdatum, vdatum,GDBM_REPLACE)<0)
    throw XDBException("Error storing key: "+string(strerror(errno)));

}

void XGDBMWrapper::del(const string &key)
{
}

#ifdef TESTDRIVER
main()
{
  try {
    XDBWrapper *xdb=new XGDBMWrapper("wuh",XDBWrapper::ReadWrite);
    xdb->put("ahu","toffe gast");
    xdb->append("ahu",", echt waar!");
    
    string tst;
    xdb->get("ahu",tst);
    cout<<"Database zegt over ahu: '"<<tst<<"'"<<endl;
    
    xdb->append("ahu"," Toch niet!");
    xdb->get("ahu",tst);
    cout<<"Database zegt over ahu: '"<<tst<<"'"<<endl;
    delete xdb;
  }
  catch(XDBException &e) {
    cerr<<"Fatal error: "<<e.what<<endl;
  }

}

#endif /* TESTDRIVER */
