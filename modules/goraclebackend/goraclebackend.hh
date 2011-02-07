#include <string>
#include <map>

#include "pdns/backends/gsql/gsqlbackend.hh"

#include "pdns/namespaces.hh"

/** The gOracleBackend is a DNSBackend that can answer DNS related questions. It looks up data
    in PostgreSQL */
class gOracleBackend : public GSQLBackend
{
public:
  gOracleBackend(const string &mode, const string &suffix); //!< Makes our connection to the database. Throws an exception if it fails.
 
private:
};
