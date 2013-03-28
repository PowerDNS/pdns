
#include <string>
#include <map>

#include "pdns/namespaces.hh"

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "goraclebackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ueberbackend.hh"
#include "pdns/ahuexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"

#include "soracle.hh"

#include <sstream>

gOracleBackend::gOracleBackend(const string &mode, const string &suffix)  : GSQLBackend(mode,suffix)
{
  try {
    // set some envionment variables
    setenv("ORACLE_HOME", getArg("home").c_str(), 1);
    setenv("ORACLE_SID", getArg("sid").c_str(), 1);
    setenv("NLS_LANG", getArg("nls-lang").c_str(), 1);
 
    setDB(new SOracle(getArg("tnsname"),
        	     getArg("user"),
        	     getArg("password")));
    
  }
  
  catch(SSqlException &e) {
    L<<Logger::Error<<mode<<" Connection failed: "<<e.txtReason()<<endl;
    throw AhuException("Unable to launch "+mode+" connection: "+e.txtReason());
  }
  L<<Logger::Warning<<mode<<" Connection successful"<<endl;
}

class gOracleFactory : public BackendFactory
{
public:
  gOracleFactory(const string &mode) : BackendFactory(mode),d_mode(mode) {}
  
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"home", "Oracle home path", "");
    declare(suffix,"sid", "Oracle sid", "XE");
    declare(suffix,"nls-lang", "Oracle language", "AMERICAN_AMERICA.AL32UTF8");

    declare(suffix,"tnsname","Generic Oracle backend TNSNAME to connect to","powerdns");
    declare(suffix,"user","Database backend user to connect as","powerdns");
    declare(suffix,"password","Pdns backend password to connect with","");

    declare(suffix,"get-all-domains-query", "Get all domain","select id,name,master,last_check,type,notified_serial,account from domains");
    declare(suffix,"basic-query","Basic query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s'");
    declare(suffix,"id-query","Basic with ID query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s' and domain_id=%d");
    declare(suffix,"wildcard-query","Wildcard query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s'");
    declare(suffix,"wildcard-id-query","Wildcard with ID query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s' and domain_id='%d'");

    declare(suffix,"any-query","Any query","select content,ttl,prio,type,domain_id,name from records where name='%s'");
    declare(suffix,"any-id-query","Any with ID query","select content,ttl,prio,type,domain_id,name from records where name='%s' and domain_id=%d");
    declare(suffix,"wildcard-any-query","Wildcard ANY query","select content,ttl,prio,type,domain_id,name from records where name like '%s'");
    declare(suffix,"wildcard-any-id-query","Wildcard ANY with ID query","select content,ttl,prio,type,domain_id,name from records where name like '%s' and domain_id='%d'");

    declare(suffix,"list-query","AXFR query", "select content,ttl,prio,type,domain_id,name from records where domain_id='%d'");
    declare(suffix,"master-zone-query","Data", "select master from domains where name='%s' and type='SLAVE'");

    declare(suffix,"info-zone-query","","select id,name,master,last_check,notified_serial,type from domains where name='%s'");

    declare(suffix,"info-all-slaves-query","","select id,name,master,last_check,type from domains where type='SLAVE'");
    declare(suffix,"supermaster-query","", "select account from supermasters where ip='%s' and nameserver='%s'");
    declare(suffix,"insert-slave-query","", "insert into domains (id, type,name,master,account) values(domain_id_sequence.nextval, 'SLAVE','%s','%s','%s')");
    declare(suffix,"insert-record-query","", "insert into records (id, content,ttl,prio,type,domain_id,name) values (records_id_sequence.nextval, '%s',%d,%d,'%s',%d,'%s')");
    declare(suffix,"update-serial-query","", "update domains set notified_serial=%d where id=%d");
    declare(suffix,"update-lastcheck-query","", "update domains set last_check=%d where id=%d");
    declare(suffix,"zone-lastchange-query", "", "select max(change_date) from records where domain_id=%d");
    declare(suffix,"info-all-master-query","", "select id,name,master,last_check,notified_serial,type from domains where type='MASTER'");
    declare(suffix,"delete-zone-query","", "delete from records where domain_id=%d");
  }
  
  DNSBackend *make(const string &suffix="")
  {
    return new gOracleBackend(d_mode,suffix);
  }
private:
  const string d_mode;
};


//! Magic class that is activated when the dynamic library is loaded
class gOracleLoader
{
public:
  //! This reports us to the main UeberBackend class
  gOracleLoader()
  {
    BackendMakers().report(new gOracleFactory("goracle"));
    L<<Logger::Warning<<"This is module goraclebackend.so reporting"<<endl;
  }
};
static gOracleLoader goracleloader;
