
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
    declare(suffix,"dnssec","Assume DNSSEC Schema is in place","no");

    declare(suffix,"basic-query","Basic query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s'");
    declare(suffix,"id-query","Basic with ID query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s' and domain_id=%d");
    declare(suffix,"wildcard-query","Wildcard query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s'");
    declare(suffix,"wildcard-id-query","Wildcard with ID query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s' and domain_id='%d'");

    declare(suffix,"any-query","Any query","select content,ttl,prio,type,domain_id,name from records where name='%s'");
    declare(suffix,"any-id-query","Any with ID query","select content,ttl,prio,type,domain_id,name from records where name='%s' and domain_id=%d");
    declare(suffix,"wildcard-any-query","Wildcard ANY query","select content,ttl,prio,type,domain_id,name from records where name like '%s'");
    declare(suffix,"wildcard-any-id-query","Wildcard ANY with ID query","select content,ttl,prio,type,domain_id,name from records where name like '%s' and domain_id='%d'");

    declare(suffix,"list-query","AXFR query", "select content,ttl,prio,type,domain_id,name from records where domain_id='%d'");

    declare(suffix,"remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "delete from records where domain_id='%d' and type is null");
    declare(suffix,"insert-empty-non-terminal-query", "insert empty non-terminal in zone", "insert into records (domain_id,name,type) values ('%d','%s',null)");
    declare(suffix,"delete-empty-non-terminal-query", "delete empty non-terminal from zone", "delete from records where domain_id='%d' and name='%s' and type is null");
  
    // and now with auth
    declare(suffix,"basic-query-auth","Basic query","select content,ttl,prio,type,domain_id,name, auth from records where type='%s' and name='%s'");
    declare(suffix,"id-query-auth","Basic with ID query","select content,ttl,prio,type,domain_id,name, auth from records where type='%s' and name='%s' and domain_id=%d");
    declare(suffix,"wildcard-query-auth","Wildcard query","select content,ttl,prio,type,domain_id,name, auth from records where type='%s' and name like '%s'");
    declare(suffix,"wildcard-id-query-auth","Wildcard with ID query","select content,ttl,prio,type,domain_id,name, auth from records where type='%s' and name like '%s' and domain_id='%d'");

    declare(suffix,"any-query-auth","Any query","select content,ttl,prio,type,domain_id,name, auth from records where name='%s'");
    declare(suffix,"any-id-query-auth","Any with ID query","select content,ttl,prio,type,domain_id,name, auth from records where name='%s' and domain_id=%d");
    declare(suffix,"wildcard-any-query-auth","Wildcard ANY query","select content,ttl,prio,type,domain_id,name, auth from records where name like '%s'");
    declare(suffix,"wildcard-any-id-query-auth","Wildcard ANY with ID query","select content,ttl,prio,type,domain_id,name, auth from records where name like '%s' and domain_id='%d'");

    declare(suffix,"list-query-auth","AXFR query", "select content,ttl,prio,type,domain_id,name, auth from records where domain_id='%d' order by name, type");

    declare(suffix,"insert-empty-non-terminal-query-auth", "insert empty non-terminal in zone", "insert into records (domain_id,name,type,auth) values ('%d','%s',null,'1')");
    
    declare(suffix,"master-zone-query","Data", "select master from domains where name='%s' and type='SLAVE'");

    declare(suffix,"info-zone-query","","select id,name,master,last_check,notified_serial,type from domains where name='%s'");

    declare(suffix,"info-all-slaves-query","","select id,name,master,last_check,type from domains where type='SLAVE'");
    declare(suffix,"supermaster-query","", "select account from supermasters where ip='%s' and nameserver='%s'");
    declare(suffix,"insert-slave-query","", "insert into domains (id, type,name,master,account) values(domain_id_sequence.nextval, 'SLAVE','%s','%s','%s')"); 
    declare(suffix,"insert-record-query","", "insert into records (id, content,ttl,prio,type,domain_id,name) values (records_id_sequence.nextval, '%s',%d,%d,'%s',%d,'%s')"); 
    declare(suffix,"insert-record-query-auth","", "insert into records (id, content,ttl,prio,type,domain_id,name,auth) values (records_id_sequence.nextval, '%s',%d,%d,'%s',%d,'%s','%d')");
    
    declare(suffix,"get-order-first-query","DNSSEC Ordering Query, first", "select ordername, name from records where domain_id=%d and ordername is not null and rownum=1 order by 1 asc");
    declare(suffix,"get-order-before-query","DNSSEC Ordering Query, before", "select ordername, name from records where ordername <= '%s' and domain_id=%d and ordername is not null and rownum=1 order by 1 desc");
    declare(suffix,"get-order-after-query","DNSSEC Ordering Query, after", "select min(ordername) from records where ordername > '%s' and domain_id=%d and ordername is not null");
    declare(suffix,"get-order-last-query","DNSSEC Ordering Query, last", "select ordername, name from records where ordername != '' and domain_id=%d and ordername is not null and rownum=1 order by 1 desc");
    declare(suffix,"set-order-and-auth-query", "DNSSEC set ordering query", "update records set ordername='%s',auth=%d where name='%s' and domain_id='%d'");
    declare(suffix,"nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth query", "update records set ordername=NULL,auth=%d where domain_id='%d' and name='%s'");
    declare(suffix,"nullify-ordername-and-auth-query", "DNSSEC nullify ordername and auth query", "update records set ordername=NULL,auth=0 where name='%s' and type='%s' and domain_id='%d'");
    declare(suffix,"set-auth-on-ds-record-query", "DNSSEC set auth on a DS record", "update records set auth=1 where domain_id='%d' and name='%s' and type='DS'");

    declare(suffix,"update-serial-query","", "update domains set notified_serial=%d where id=%d");
    declare(suffix,"update-lastcheck-query","", "update domains set last_check=%d where id=%d");
    declare(suffix,"zone-lastchange-query", "", "select max(change_date) from records where domain_id=%d");
    declare(suffix,"info-all-master-query","", "select id,name,master,last_check,notified_serial,type from domains where type='MASTER'");
    declare(suffix,"delete-zone-query","", "delete from records where domain_id=%d");
    declare(suffix,"delete-rrset-query","","delete from records where domain_id=%d and name='%s' and type='%s'");
    declare(suffix,"add-domain-key-query","", "insert into cryptokeys (id, domain_id, flags, active, content) select cryptokeys_id_sequence.nextval, id, %d, %d, '%s' from domains where name='%s'");
    declare(suffix,"list-domain-keys-query","", "select cryptokeys.id, flags, active, content from domains, cryptokeys where cryptokeys.domain_id=domains.id and name='%s'");
    declare(suffix,"get-domain-metadata-query","", "select content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name='%s' and domainmetadata.kind='%s'");
    declare(suffix,"clear-domain-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name='%s') and domainmetadata.kind='%s'");
    declare(suffix,"set-domain-metadata-query","", "insert into domainmetadata (id, domain_id, kind, content) select domainmetadata_sequence_id.nextval, id, '%s', '%s' from domains where name='%s'");
    declare(suffix,"activate-domain-key-query","", "update cryptokeys set active=1 where domain_id=(select id from domains where name='%s') and  cryptokeys.id=%d");
    declare(suffix,"deactivate-domain-key-query","", "update cryptokeys set active=0 where domain_id=(select id from domains where name='%s') and  cryptokeys.id=%d");
    declare(suffix,"remove-domain-key-query","", "delete from cryptokeys where domain_id=(select id from domains where name='%s') and cryptokeys.id=%d");    
    declare(suffix,"get-tsig-key-query","", "select algorithm, secret from tsigkeys where name='%s'");

    declare(suffix,"get-all-domains-query", "Retrieve all domains", "select records.domain_id, records.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check from records, domains where records.domain_id=domains.id and records.type='SOA'");

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
