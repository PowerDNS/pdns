#include <string>
#include <map>
#include "ssql.hh"
#include "pdns/backends/gsql/gsqlbackend.hh"

using namespace std;

/** The gMySQLBackend is a DNSBackend that can answer DNS related questions. It looks up data
    in PostgreSQL */
class gMySQLBackend : public GSQLBackend
{
public:
  gMySQLBackend(const string &mode, const string &suffix); //!< Makes our connection to the database. Throws an exception if it fails.
 
private:
};
