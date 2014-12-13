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
#include "gmysqlbackend.hh"
#include "smysql.hh"
#include <sstream>

gMySQLBackend::gMySQLBackend(const string &mode, const string &suffix)  : GSQLBackend(mode,suffix)
{
  try {
    setDB(new SMySQL(getArg("dbname"),
                     getArg("host"),
                     getArgAsNum("port"),
                     getArg("socket"),
                     getArg("user"),
                     getArg("password"),
                     getArg("group"),
                     mustDo("innodb-read-committed")));
  }

  catch(SSqlException &e) {
    L<<Logger::Error<<mode<<" Connection failed: "<<e.txtReason()<<endl;
    throw PDNSException("Unable to launch "+mode+" connection: "+e.txtReason());
  }
  L<<Logger::Info<<mode<<" Connection successful. Connected to database '"<<getArg("dbname")<<"' on '"<<(getArg("host").empty() ? getArg("socket") : getArg("host"))<<"'."<<endl;
}

class gMySQLFactory : public BackendFactory
{
public:
  gMySQLFactory(const string &mode) : BackendFactory(mode),d_mode(mode) {}

  void declareArguments(const string &suffix="")
  {
    declare(suffix,"dbname","Pdns backend database name to connect to","powerdns");
    declare(suffix,"user","Database backend user to connect as","powerdns");
    declare(suffix,"host","Database backend host to connect to","");
    declare(suffix,"port","Database backend port to connect to","0");
    declare(suffix,"socket","Pdns backend socket to connect to","");
    declare(suffix,"password","Pdns backend password to connect with","");
    declare(suffix,"group", "Pdns backend MySQL 'group' to connect as", "client");
    declare(suffix,"innodb-read-committed","Use InnoDB READ-COMMITTED transaction isolation level","yes");

    declare(suffix,"dnssec","Enable DNSSEC processing","no");

    string record_query = "SELECT content, ttl, prio, type, domain_id, disabled, name, auth FROM records WHERE";

    declare(suffix, "basic-query", "Basic query", record_query+" disabled=0 AND type='%s' AND name='%s'");
    declare(suffix, "id-query", "Basic with ID query", record_query+" disabled=0 AND type='%s' AND name='%s' AND domain_id=%d");
    declare(suffix, "any-query", "Any query", record_query+" disabled=0 AND name='%s'");
    declare(suffix, "any-id-query", "Any with ID query", record_query+" disabled=0 AND name='%s' AND domain_id=%d");

    declare(suffix, "list-query", "AXFR query", record_query+" (disabled=0 OR %d) AND domain_id='%d' ORDER BY name, type");
    declare(suffix, "list-subzone-query", "Subzone listing", record_query+" disabled=0 AND (name='%s' OR name LIKE '%s') AND domain_id='%d'");

    declare(suffix, "remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "DELETE FROM records WHERE domain_id='%d' AND type IS NULL");
    declare(suffix, "insert-empty-non-terminal-query", "insert empty non-terminal in zone", "INSERT INTO records (domain_id, name, type, disabled, auth) VALUES ('%d', '%s', NULL, 0, '1')");
    declare(suffix, "delete-empty-non-terminal-query", "delete empty non-terminal from zone", "DELETE FROM records WHERE domain_id='%d' AND name='%s' AND type IS NULL");

    declare(suffix,"master-zone-query","Data", "SELECT master FROM domains WHERE name='%s' AND type='SLAVE'");

    declare(suffix,"info-zone-query","","SELECT id, name, master, last_check, notified_serial, type FROM domains WHERE name='%s'");

    declare(suffix,"info-all-slaves-query","","SELECT id, name, master, last_check, type FROM domains WHERE type='SLAVE'");
    declare(suffix,"supermaster-query","", "SELECT account FROM supermasters WHERE ip='%s' AND nameserver='%s'");
    declare(suffix,"supermaster-name-to-ips", "", "SELECT ip, account FROM supermasters WHERE nameserver='%s' AND account='%s'");

    declare(suffix,"insert-zone-query","", "INSERT INTO domains (type, name) VALUES ('NATIVE', '%s')");
    declare(suffix,"insert-slave-query","", "INSERT INTO domains (type, name, master, account) VALUES ('SLAVE', '%s', '%s', '%s')");

    declare(suffix, "insert-record-query", "", "INSERT INTO records (content, ttl, prio, type, domain_id, disabled, name, auth) VALUES ('%s', %d, %d, '%s', %d, %d, '%s', '%d')");
    declare(suffix, "insert-record-order-query", "", "INSERT INTO records (content, ttl, prio, type, domain_id, disabled, name, ordername, auth) VALUES ('%s', %d, %d, '%s', %d, %d, '%s', '%s', '%d')");
    declare(suffix, "insert-ent-query", "insert empty non-terminal in zone", "INSERT INTO records (type, domain_id, disabled, name, auth) VALUES (NULL, '%d', 0, '%s', '%d')");
    declare(suffix, "insert-ent-order-query", "insert empty non-terminal in zone", "INSERT INTO records (type, domain_id, disabled, name, ordername, auth) VALUES (NULL, '%d', 0, '%s', '%s', '%d')");

    declare(suffix, "get-order-first-query", "DNSSEC Ordering Query, first", "SELECT ordername, name FROM records WHERE domain_id=%d AND disabled=0 AND ordername IS NOT NULL ORDER BY 1 ASC LIMIT 1");
    declare(suffix, "get-order-before-query", "DNSSEC Ordering Query, before", "SELECT ordername, name FROM records WHERE ordername <= '%s' AND domain_id=%d AND disabled=0 AND ordername IS NOT NULL ORDER BY 1 DESC LIMIT 1");
    declare(suffix, "get-order-after-query", "DNSSEC Ordering Query, after", "SELECT MIN(ordername) FROM records WHERE ordername > '%s' AND domain_id=%d AND disabled=0 AND ordername IS NOT NULL");
    declare(suffix, "get-order-last-query", "DNSSEC Ordering Query, last", "SELECT ordername, NAME FROM records WHERE ordername != '' AND domain_id=%d AND disabled=0 AND ordername IS NOT NULL ORDER BY 1 DESC LIMIT 1");
    declare(suffix, "set-order-and-auth-query", "DNSSEC set ordering query", "UPDATE records SET ordername='%s',auth=%d WHERE name='%s' AND domain_id='%d' AND disabled=0");
    declare(suffix, "set-auth-on-ds-record-query", "DNSSEC set auth on a DS record", "UPDATE records SET auth=1 WHERE domain_id='%d' AND name='%s' AND type='DS' AND disabled=0");

    declare(suffix, "nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth query", "UPDATE records SET ordername=NULL, auth=%d WHERE domain_id='%d' AND name='%s' AND disabled=0");
    declare(suffix, "nullify-ordername-and-auth-query", "DNSSEC nullify ordername and auth query", "UPDATE records SET ordername=NULL, auth=0 WHERE name='%s' AND type='%s' AND domain_id='%d' AND disabled=0");

    declare(suffix,"update-master-query","", "UPDATE domains SET master='%s' WHERE name='%s'");
    declare(suffix,"update-kind-query","", "UPDATE domains SET type='%s' WHERE name='%s'");
    declare(suffix,"update-serial-query","", "UPDATE domains SET notified_serial=%d WHERE id=%d");
    declare(suffix,"update-lastcheck-query","", "UPDATE domains SET last_check=%d WHERE id=%d");
    declare(suffix,"zone-lastchange-query", "", "SELECT MAX(change_date) FROM records WHERE domain_id=%d");
    declare(suffix,"info-all-master-query","", "SELECT id, name, master, last_check, notified_serial, type FROM domains WHERE type='MASTER'");
    declare(suffix,"delete-domain-query","", "DELETE FROM domains WHERE name='%s'");
    declare(suffix,"delete-zone-query","", "DELETE FROM records WHERE domain_id=%d");
    declare(suffix,"delete-rrset-query","","DELETE FROM records WHERE domain_id=%d AND name='%s' AND type='%s'");
    declare(suffix,"delete-names-query","","DELETE FROM records WHERE domain_id=%d AND name='%s'");

    declare(suffix,"add-domain-key-query","", "INSERT INTO cryptokeys (domain_id, flags, active, content) SELECT id, %d, %d, '%s' FROM domains WHERE name='%s'");
    declare(suffix,"list-domain-keys-query","", "SELECT cryptokeys.id, flags, active, content FROM domains, cryptokeys WHERE cryptokeys.domain_id=domains.id AND name='%s'");
    declare(suffix,"get-all-domain-metadata-query","", "SELECT kind,content FROM domains, domainmetadata WHERE domainmetadata.domain_id=domains.id AND name='%s'");
    declare(suffix,"get-domain-metadata-query","", "SELECT content FROM domains, domainmetadata WHERE domainmetadata.domain_id=domains.id AND name='%s' AND domainmetadata.kind='%s'");
    declare(suffix,"clear-domain-metadata-query","", "DELETE FROM domainmetadata WHERE domain_id=(SELECT id FROM domains WHERE name='%s') AND domainmetadata.kind='%s'");
    declare(suffix,"clear-domain-all-metadata-query","", "DELETE FROM domainmetadata WHERE domain_id=(SELECT id FROM domains WHERE name='%s')");
    declare(suffix,"set-domain-metadata-query","", "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, '%s', '%s' FROM domains WHERE name='%s'");
    declare(suffix,"activate-domain-key-query","", "UPDATE cryptokeys SET active=1 WHERE domain_id=(SELECT id FROM domains WHERE name='%s') AND cryptokeys.id=%d");
    declare(suffix,"deactivate-domain-key-query","", "UPDATE cryptokeys SET active=0 WHERE domain_id=(SELECT id FROM domains WHERE name='%s') AND cryptokeys.id=%d");
    declare(suffix,"remove-domain-key-query","", "DELETE FROM cryptokeys WHERE domain_id=(SELECT id FROM domains WHERE name='%s') AND cryptokeys.id=%d");
    declare(suffix,"clear-domain-all-keys-query","", "DELETE FROM cryptokeys WHERE domain_id=(SELECT id FROM domains WHERE name='%s')");
    declare(suffix,"get-tsig-key-query","", "SELECT algorithm, secret FROM tsigkeys WHERE name='%s'");
    declare(suffix,"set-tsig-key-query","", "REPLACE INTO tsigkeys (name, algorithm, secret) VALUES ('%s', '%s', '%s')");
    declare(suffix,"delete-tsig-key-query","", "DELETE FROM tsigkeys WHERE name='%s'");
    declare(suffix,"get-tsig-keys-query","", "SELECT name, algorithm, secret FROM tsigkeys");

    declare(suffix, "get-all-domains-query", "Retrieve all domains", "SELECT domains.id, domains.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check FROM domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name WHERE records.disabled=0 OR %d");

    declare(suffix, "list-comments-query", "", "SELECT domain_id, name, type, modified_at, account, comment FROM comments WHERE domain_id=%d");
    declare(suffix, "insert-comment-query", "", "INSERT INTO comments (domain_id, name, type, modified_at, account, comment) VALUES (%d, '%s', '%s', %d, '%s', '%s')");
    declare(suffix, "delete-comment-rrset-query", "", "DELETE FROM comments WHERE domain_id=%d AND name='%s' AND type='%s'");
    declare(suffix, "delete-comments-query", "", "DELETE FROM comments WHERE domain_id=%d");
  }

  DNSBackend *make(const string &suffix="")
  {
    return new gMySQLBackend(d_mode,suffix);
  }
private:
  const string d_mode;
};


//! Magic class that is activated when the dynamic library is loaded
class gMySQLLoader
{
public:
  //! This reports us to the main UeberBackend class
  gMySQLLoader()
  {
    BackendMakers().report(new gMySQLFactory("gmysql"));
    L << Logger::Info << "[gmysqlbackend] This is the gmysql backend version " VERSION " (" __DATE__ ", " __TIME__ ") reporting" << endl;
  }
};
static gMySQLLoader gmysqlloader;
