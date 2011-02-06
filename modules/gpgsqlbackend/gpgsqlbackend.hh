#include <string>
#include <map>
#include "pdns/backends/gsql/gsqlbackend.hh"

#include "pdns/namespaces.hh"

/** The gPgSQLBackend is a DNSBackend that can answer DNS related questions. It looks up data
    in PostgreSQL */
class gPgSQLBackend : public GSQLBackend
{
public:
  gPgSQLBackend(const string &mode, const string &suffix); //!< Makes our connection to the database. Throws an exception if it fails.

};
