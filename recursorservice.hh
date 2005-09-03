/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef AHUDNSSERVICE_HH
#define AHUDNSSERVICE_HH

#include <string>
#include "ntservice.hh"

class RecursorService : public NTService
{
protected:
  //! Main service procedure.
  int main( int argc, char *argv[] );

  //! Control handler.
  void ctrlHandler( DWORD controlCode );
  
public:
  //! Constructor.
  RecursorService( void ) : NTService()
  {
  }
  
  //! Returns the service name.
  std::string getServiceName( void );
  
};

#endif // AHUDNSSERVICE_HH
