
#include <string>
#include <map>
#include "pdns/namespaces.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ueberbackend.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "goraclebackend.hh"
#include "soracle.hh"
#include <sstream>

gOracleBackend::gOracleBackend(const string &mode, const string &suffix)  : GSQLBackend(mode, suffix)
{
  try {
    // set Oracle envionment variables
    setenv("ORACLE_HOME", getArg("home").c_str(), 1);
    setenv("ORACLE_SID", getArg("sid").c_str(), 1);
    setenv("NLS_LANG", getArg("nls-lang").c_str(), 1);

    setDB(new SOracle(getArg("tnsname"),
                      getArg("user"),
                      getArg("password")));

  }

  catch (SSqlException &e) {
    L<<Logger::Error << mode << " Connection failed: " << e.txtReason() << endl;
    throw PDNSException("Unable to launch " + mode + " connection: " + e.txtReason());
  }
  L<<Logger::Info << mode << " Connection successful" << endl;
}


string gOracleBackend::sqlEscape(const string &name)
{
  return boost::replace_all_copy(name, "'", "''");
}


class gOracleFactory : public BackendFactory
{
public:
  gOracleFactory(const string &mode) : BackendFactory(mode), d_mode(mode) {}

  void declareArguments(const string &suffix="") {
    declare(suffix,"home", "Oracle home path", "");
    declare(suffix,"sid", "Oracle sid", "XE");
    declare(suffix,"nls-lang", "Oracle language", "AMERICAN_AMERICA.AL32UTF8");

    declare(suffix,"tnsname","Generic Oracle backend TNSNAME to connect to","powerdns");
    declare(suffix,"user","Database backend user to connect as","powerdns");
    declare(suffix,"password","Pdns backend password to connect with","");

    declare(suffix,"dnssec","Enable DNSSEC processing","no");

    string record_query = "SELECT content,ttl,prio,type,domain_id,disabled,name,auth FROM records WHERE";

    declare(suffix, "basic-query", "Basic query", record_query+" disabled=0 and type='%s' and name='%s'");
    declare(suffix, "id-query", "Basic with ID query", record_query+" disabled=0 and type='%s' and name='%s' and domain_id=%d");
    declare(suffix, "any-query", "Any query", record_query+" disabled=0 and name='%s'");
    declare(suffix, "any-id-query", "Any with ID query", record_query+" disabled=0 and name='%s' and domain_id=%d");

    declare(suffix, "list-query", "AXFR query", record_query+" (disabled=0 OR 1=%d) and domain_id='%d' order by name, type");
    declare(suffix, "list-subzone-query", "Subzone listing", record_query+" disabled=0 and (name='%s' OR name like '%s') and domain_id='%d'");

    declare(suffix, "remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "delete from records where domain_id='%d' and type is null");
    declare(suffix, "insert-empty-non-terminal-query", "insert empty non-terminal in zone", "insert into records (id,domain_id,name,type,disabled,auth) values (records_id_sequence.nextval,'%d','%s',null,0,'1')");
    declare(suffix,"delete-empty-non-terminal-query", "delete empty non-terminal from zone", "delete from records where domain_id='%d' and name='%s' and type is null");

    declare(suffix,"master-zone-query","Data", "select master from domains where name='%s' and type='SLAVE'");

    declare(suffix,"info-zone-query","","select id,name,master,last_check,notified_serial,type from domains where name='%s'");

    declare(suffix,"info-all-slaves-query","","select id,name,master,last_check,type from domains where type='SLAVE'");
    declare(suffix,"supermaster-query","", "select account from supermasters where ip='%s' and nameserver='%s'");
    declare(suffix,"supermaster-name-to-ips", "", "select ip,account from supermasters where nameserver='%s' and account='%s'");

    declare(suffix,"insert-zone-query","", "insert into domains (id, type, name) values(domain_id_sequence.nextval, 'NATIVE','%s')");
    declare(suffix,"insert-slave-query","", "insert into domains (id, type,name,master,account) values(domain_id_sequence.nextval, 'SLAVE','%s','%s','%s')");

    declare(suffix, "insert-record-query", "", "insert into records (id, content,ttl,prio,type,domain_id,disabled,name,auth) values (records_id_sequence.nextval, '%s',%d,%d,'%s',%d,%d,'%s','%d')");
    declare(suffix, "insert-record-order-query", "", "insert into records (id, content,ttl,prio,type,domain_id,disabled,name,ordername,auth) values (records_id_sequence.nextval, '%s',%d,%d,'%s',%d,%d,'%s','%s ','%d')");
    declare(suffix, "insert-ent-query", "insert empty non-terminal in zone", "insert into records (id, type,domain_id,disabled,name,auth) values (records_id_sequence.nextval, null,'%d',0,'%s','%d')");
    declare(suffix, "insert-ent-order-query", "insert empty non-terminal in zone", "insert into records (id, type,domain_id,disabled,name,ordername,auth) values (records_id_sequence.nextval, null,'%d',0,'%s','%s','%d')");

    declare(suffix, "get-order-first-query", "DNSSEC Ordering Query, first", "select trim(ordername),name from records where disabled=0 and domain_id=%d and ordername is not null and rownum=1 order by ordername asc");
    declare(suffix, "get-order-before-query", "DNSSEC Ordering Query, before", "select trim(ordername), name from records where disabled=0 and ordername <= '%s ' and domain_id=%d and ordername is not null and rownum=1 order by ordername desc");
    declare(suffix, "get-order-after-query", "DNSSEC Ordering Query, after", "select trim(min(ordername)) from records where disabled=0 and ordername > '%s ' and domain_id=%d and ordername is not null");
    declare(suffix, "get-order-last-query", "DNSSEC Ordering Query, last", "select trim(ordername), name from records where disabled=0 and ordername != ' ' and domain_id=%d and ordername is not null and rownum=1 order by ordername desc");
    declare(suffix, "set-order-and-auth-query", "DNSSEC set ordering query", "update records set ordername='%s ',auth=%d where name='%s' and domain_id='%d' and disabled=0");
    declare(suffix, "set-auth-on-ds-record-query", "DNSSEC set auth on a DS record", "update records set auth=1 where domain_id='%d' and name='%s' and type='DS' and disabled=0");

    declare(suffix, "nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth query", "update records set ordername=NULL,auth=%d where domain_id='%d' and name='%s' and disabled=0");
    declare(suffix, "nullify-ordername-and-auth-query", "DNSSEC nullify ordername and auth query", "update records set ordername=NULL,auth=0 where name='%s' and type='%s' and domain_id='%d' and disabled=0");

    declare(suffix,"update-master-query","", "update domains set master='%s' where name='%s'");
    declare(suffix,"update-kind-query","", "update domains set type='%s' where name='%s'");
    declare(suffix,"update-serial-query","", "update domains set notified_serial=%d where id=%d");
    declare(suffix,"update-lastcheck-query","", "update domains set last_check=%d where id=%d");
    declare(suffix,"zone-lastchange-query", "", "select max(change_date) from records where domain_id=%d");
    declare(suffix,"info-all-master-query","", "select id,name,master,last_check,notified_serial,type from domains where type='MASTER'");
    declare(suffix,"delete-domain-query","", "delete from domains where name='%s'");
    declare(suffix,"delete-zone-query","", "delete from records where domain_id=%d");
    declare(suffix,"delete-rrset-query","","delete from records where domain_id=%d and name='%s' and type='%s'");
    declare(suffix,"delete-names-query","","delete from records where domain_id=%d and name='%s'");

    declare(suffix,"add-domain-key-query","", "insert into cryptokeys (id, domain_id, flags, active, content) select cryptokeys_id_sequence.nextval, id, %d, %d, '%s' from domains where name='%s'");
    declare(suffix,"list-domain-keys-query","", "select cryptokeys.id, flags, active, content from domains, cryptokeys where cryptokeys.domain_id=domains.id and name='%s'");
    declare(suffix,"get-all-domain-metadata-query","", "select kind,content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name='%s'");
    declare(suffix,"get-domain-metadata-query","", "select content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name='%s' and domainmetadata.kind='%s'");
    declare(suffix,"clear-domain-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name='%s') and domainmetadata.kind='%s'");
    declare(suffix,"clear-domain-all-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name='%s')");
    declare(suffix,"set-domain-metadata-query","", "insert into domainmetadata (id, domain_id, kind, content) select domainmetadata_id_sequence.nextval, id, '%s', '%s' from domains where name='%s'");
    declare(suffix,"activate-domain-key-query","", "update cryptokeys set active=1 where domain_id=(select id from domains where name='%s') and  cryptokeys.id=%d");
    declare(suffix,"deactivate-domain-key-query","", "update cryptokeys set active=0 where domain_id=(select id from domains where name='%s') and  cryptokeys.id=%d");
    declare(suffix,"remove-domain-key-query","", "delete from cryptokeys where domain_id=(select id from domains where name='%s') and cryptokeys.id=%d");
    declare(suffix,"clear-domain-all-keys-query","", "delete from cryptokeys where domain_id=(select id from domains where name='%s')");
    declare(suffix,"get-tsig-key-query","", "select algorithm, secret from tsigkeys where name='%s'");
    declare(suffix,"set-tsig-key-query","", "insert into tsigkeys (id,name,algorithm,secret) VALUES(tsigkeys_id_sequence.nextval,'%s','%s','%s')");
    declare(suffix,"delete-tsig-key-query","", "delete from tsigkeys where name='%s'");
    declare(suffix,"get-tsig-keys-query","", "select name,algorithm, secret from tsigkeys");

    declare(suffix, "get-all-domains-query", "Retrieve all domains", "select domains.id, domains.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check from domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name WHERE records.disabled=0 OR 1=%d");

    declare(suffix, "list-comments-query", "", "SELECT domain_id,name,type,modified_at,account,\"comment\" FROM comments WHERE domain_id=%d");
    declare(suffix, "insert-comment-query", "", "INSERT INTO comments (id, domain_id, name, type, modified_at, account, \"comment\") VALUES (comments_id_sequence.nextval, %d, '%s', '%s', %d, '%s', '%s')");
    declare(suffix, "delete-comment-rrset-query", "", "DELETE FROM comments WHERE domain_id=%d AND name='%s' AND type='%s'");
    declare(suffix, "delete-comments-query", "", "DELETE FROM comments WHERE domain_id=%d");
  }

  DNSBackend* make(const string &suffix="") {
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
  gOracleLoader() {
    BackendMakers().report(new gOracleFactory("goracle"));
    L << Logger::Info << "[goraclebackend] This is the goracle backend version " VERSION " reporting" << endl;
  }
};

//! Reports the backendloader to the UeberBackend.
static gOracleLoader goracleloader;
