/*
    Copyright (C) 2011 Fredrik Danerklint

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published 
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "mongodbbackend.hh"
#include "pdns/logger.hh"

/* SECOND PART */

class MONGODBFactory : public BackendFactory
{
public:
  MONGODBFactory() : BackendFactory("mongodb") {}
  
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"host","which mongodb server to connect to","localhost:27017");
    declare(suffix,"database","which database to use","dns");
    declare(suffix,"user","which user to authenticate with","");
    declare(suffix,"password","which password to use with authentication","");

    declare(suffix,"collection-domains","name of the collections for domains","domains");
    declare(suffix,"collection-records","name of the collections for records","records");
    declare(suffix,"collection-domainmetadata","name of the collections for domainmetadata","domainmetadata");
    declare(suffix,"collection-cryptokeys","name of the collections for cryptokeys","cryptokeys");
    declare(suffix,"collection-tsigkeys","name of the collections for cryptokeys","tsigkeys");

    declare(suffix, "dnssec", "Using DNSSEC","yes");
    declare(suffix, "checkindex", "Creating the index if needed","no");
    declare(suffix, "logging-query", "Logging query(s)","no");
    declare(suffix, "logging-cerr", "Logging message(s) to cerr","no");
    declare(suffix, "logging-content", "Logging the content ","no");
    declare(suffix, "use-default-ttl", "If we should use soa.ttl if soa.ttl is less than soa.default_ttl ","no");

  }
  
  DNSBackend *make(const string &suffix="")
  {
    return new MONGODBBackend(suffix);
  }
  
};

/* THIRD PART */

class MONGODBLoader
{
public:
  MONGODBLoader()
  {
    BackendMakers().report(new MONGODBFactory);
    
    L<<Logger::Notice<<"[MONGODBBackend] This is the mongodbbackend ("__DATE__", "__TIME__") reporting"<<endl;
  }  
};

static MONGODBLoader mongodbLoader;
