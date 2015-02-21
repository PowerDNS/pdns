#ifndef PDNS_GMYSQLBACKEND_HH
#define PDNS_GMYSQLBACKEND_HH

#include <string>
#include <map>
#include "pdns/backends/gsql/gsqlbackend.hh"

#include "pdns/namespaces.hh"

/** The gMySQLBackend is a DNSBackend that can answer DNS related questions. It looks up data
    in MySQL */
class gMySQLBackend : public GSQLBackend
{
public:
  gMySQLBackend(const string &mode, const string &suffix); //!< Makes our connection to the database. Throws an exception if it fails.
};

#endif /* PDNS_GMYSQLBACKEND_HH */
