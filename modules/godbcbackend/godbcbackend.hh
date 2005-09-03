// The Generic ODBC Backend
// By Michel Stol <michel@powerdns.com>

#include <string>
#include "backends/gsql/gsqlbackend.hh"

class gODBCBackend : public GSQLBackend
{
private:
public:
  //! Constructor that connects to the database, throws an exception if something went wrong.
  gODBCBackend( const std::string & mode, const std::string & suffix );

};

