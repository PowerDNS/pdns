// $Id: gpgsqlbackend.cc,v 1.1 2002/12/16 18:02:09 ahu Exp $ 
#include <string>
#include <map>

using namespace std;

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "gpgsqlbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ueberbackend.hh"
#include "pdns/ahuexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"

#include "spgsql.hh"


#include <sstream>

gPgSQLBackend::gPgSQLBackend(const string &mode, const string &suffix)  : GSQLBackend(mode,suffix)
{
  try {
    setDB(new SPgSQL(getArg("dbname"),
		  getArg("host"),
		  getArg("socket"),
		  getArg("user"),
		  getArg("password")));
    
  }
  
  catch(SSqlException &e) {
    L<<Logger::Error<<mode<<" Connection failed: "<<e.txtReason()<<endl;
    throw AhuException("Unable to launch "+mode+" connection: "+e.txtReason());
  }
  L<<Logger::Warning<<mode<<" Connection succesful"<<endl;
}

class gPgSQLFactory : public BackendFactory
{
public:
  gPgSQLFactory(const string &mode) : BackendFactory(mode),d_mode(mode) {}
  
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"dbname","Pdns backend database name to connect to","powerdns");
    declare(suffix,"user","Pdns backend user to connect as","powerdns");
    declare(suffix,"host","Pdns backend host to connect to","");
    declare(suffix,"socket","Pdns backend socket to connect to","");
    declare(suffix,"password","Pdns backend password to connect with","");

    declare(suffix,"basic-query","Basic query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s'");
    declare(suffix,"id-query","Basic with ID query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s' and domain_id=%d");
    declare(suffix,"wildcard-query","Wildcard query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s'");
    declare(suffix,"wildcard-id-query","Wildcard with ID query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s' and domain_id='%d'");

    declare(suffix,"any-query","Any query","select content,ttl,prio,type,domain_id,name from records where name='%s'");
    declare(suffix,"any-id-query","Any with ID query","select content,ttl,prio,type,domain_id,name from records where name='%s' and domain_id=%d");
    declare(suffix,"wildcard-any-query","Wildcard ANY query","select content,ttl,prio,type,domain_id,name from records where name like '%s'");
    declare(suffix,"wildcard-any-id-query","Wildcard ANY with ID query","select content,ttl,prio,type,domain_id,name from records where like '%s' and domain_id='%d'");

    declare(suffix,"list-query","AXFR query", "select content,ttl,prio,type,domain_id,name from records where domain_id='%d'");

  }
  
  DNSBackend *make(const string &suffix="")
  {
    return new gPgSQLBackend(d_mode,suffix);
  }
private:
  const string d_mode;
};


//! Magic class that is activated when the dynamic library is loaded
class gPgSQLLoader
{
public:
  //! This reports us to the main UeberBackend class
  gPgSQLLoader()
  {
    BackendMakers().report(new gPgSQLFactory("gpgsql"));
    BackendMakers().report(new gPgSQLFactory("gpgsql2"));
    L<<Logger::Warning<<"This is module gmysqlbackend.so reporting"<<endl;
  }
};
static gPgSQLLoader gpgsqlloader;
