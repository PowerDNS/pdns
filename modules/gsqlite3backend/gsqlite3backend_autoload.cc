#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"
#include "gsqlite3backend.hh"

//! Magic class that is activated when the dynamic library is loaded
class gSQLite3Loader
{
public:
  //! This reports us to the main UeberBackend class
  gSQLite3Loader()
  {
    BackendMakers().report( new gSQLite3Factory( "gsqlite3" ));
    g_log << Logger::Info << "[gsqlite3] This is the gsqlite3 backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};

//! Reports the backendloader to the UeberBackend.
static gSQLite3Loader gsqlite3loader;
