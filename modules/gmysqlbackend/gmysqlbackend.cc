// $Id: gmysqlbackend.cc,v 1.6 2002/12/13 15:22:33 ahu Exp $ 
#include <string>
#include <map>

using namespace std;

#include "dns.hh"
#include "dnsbackend.hh"
#include "gmysqlbackend.hh"
#include "dnspacket.hh"
#include "ueberbackend.hh"
#include "ahuexception.hh"
#include "logger.hh"
#include "arguments.hh"

#ifdef PDNS_DOMYSQL
#include "smysql.hh"
#endif

#ifdef PDNS_DOPGSQL
#include "spgsql.hh"
#endif

#include <sstream>


void gMySQLBackend::setNotified(u_int32_t domain_id, u_int32_t serial)
{
  try {
    d_db->doQuery("update domains set notified_serial="+itoa(serial)+" where id="+itoa(domain_id));
  }
  catch(SSqlException &e) {
    throw AhuException("gMySQLBackend unable to refresh domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
}

void gMySQLBackend::setFresh(u_int32_t domain_id)
{
  try {
    d_db->doQuery("update domains set last_check="+itoa(time(0))+" where id="+itoa(domain_id));
  }
  catch (SSqlException &e) {
    throw AhuException("gMySQLBackend unable to refresh domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
}

bool gMySQLBackend::isMaster(const string &domain, const string &ip)
{
  try {
    d_db->doQuery("select master from domains where name='"+sqlEscape(domain)+"' and type='SLAVE'", d_result);
  }
  catch (SSqlException &e) {
    throw AhuException("gMySQLBackend unable to retrieve list of slave domains: "+e.txtReason());
  }

  if(d_result.empty())
    return 0;
  
  return !strcmp(ip.c_str(),d_result[0][0].c_str());
}

bool gMySQLBackend::getDomainInfo(const string &domain, DomainInfo &di)
{
  /* list all domains that need refreshing for which we are slave, and insert into SlaveDomain:
     id,name,master IP,serial */
  
  try {
    d_db->doQuery("select id,name,master,last_check,notified_serial,type from domains where name='"+sqlEscape(domain)+"'",d_result);
  }
  catch(SSqlException &e) {
    throw AhuException("gMySQLBackend unable to retrieve information about a domain: "+e.txtReason());
  }

  int numanswers=d_result.size();
  if(!numanswers)
    return false;
  
  di.id=atol(d_result[0][0].c_str());
  di.zone=d_result[0][1];
  di.master=d_result[0][2];
  di.last_check=atol(d_result[0][3].c_str());
  di.backend=this;
  
  string type=d_result[0][4];
  if(type=="SLAVE")
    di.kind=DomainInfo::Slave;
  else if(type=="MASTER")
    di.kind=DomainInfo::Slave;
  else 
    di.kind=DomainInfo::Native;
  
  return true;
}

void gMySQLBackend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  /* list all domains that need refreshing for which we are slave, and insert into SlaveDomain:
     id,name,master IP,serial */

  try {
    d_db->doQuery("select id,name,master,last_check,type from domains where type='SLAVE'",d_result);
  }
  catch (SSqlException &e) {
    throw AhuException("gMySQLBackend unable to retrieve list of slave domains: "+e.txtReason());
  }

  vector<DomainInfo>allSlaves;
  int numanswers=d_result.size();
  for(int n=0;n<numanswers;++n) { // id,name,master,last_check
    DomainInfo sd;
    sd.id=atol(d_result[n][0].c_str());
    sd.zone=d_result[n][1];
    sd.master=d_result[n][2];
    sd.last_check=atol(d_result[n][3].c_str());
    sd.backend=this;
    sd.kind=DomainInfo::Slave;
    allSlaves.push_back(sd);
  }

  for(vector<DomainInfo>::iterator i=allSlaves.begin();i!=allSlaves.end();++i) {
    SOAData sdata;
    sdata.serial=0;
    sdata.refresh=0;
    getSOA(i->zone,sdata);
    if((time_t)(i->last_check+sdata.refresh) < time(0)) {
      i->serial=sdata.serial;
      unfreshDomains->push_back(*i);
    }
  }
}

void gMySQLBackend::getUpdatedMasters(vector<DomainInfo> *updatedDomains)
{
  /* list all domains that need notifications for which we are master, and insert into updatedDomains
     id,name,master IP,serial */

  try {
    d_db->doQuery("select id,name,master,last_check,notified_serial,type from domains where type='MASTER'",d_result);
  }
  catch(SSqlException &e) {
    throw AhuException("gMySQLBackend unable to retrieve list of master domains: "+e.txtReason());
  }

  vector<DomainInfo>allMasters;
  int numanswers=d_result.size();
  for(int n=0;n<numanswers;++n) { // id,name,master,last_check
    DomainInfo sd;
    sd.id=atol(d_result[n][0].c_str());
    sd.zone=d_result[n][1];
    sd.master=d_result[n][2];
    sd.last_check=atol(d_result[n][3].c_str());
    sd.notified_serial=atoi(d_result[n][4].c_str());
    sd.backend=this;
    sd.kind=DomainInfo::Master;
    allMasters.push_back(sd);
  }

  for(vector<DomainInfo>::iterator i=allMasters.begin();i!=allMasters.end();++i) {
    SOAData sdata;
    sdata.serial=0;
    sdata.refresh=0;
    getSOA(i->zone,sdata);
    if(i->notified_serial!=sdata.serial) {
      i->serial=sdata.serial;
      updatedDomains->push_back(*i);
    }
  }
}


string gMySQLBackend::sqlEscape(const string &name)
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i)
    if(*i=='\'' || *i=='\\'){
      a+='\\';
      a+=*i;
    }
    else
      a+=*i;
  return a;
}


gMySQLBackend::gMySQLBackend(const string &mode, const string &suffix)
{
  setArgPrefix(mode+suffix);

  d_logprefix="["+mode+"Backend"+suffix+"] ";
  d_db=0;
  try {
    if(0) {}
#ifdef PDNS_DOMYSQL
    else if(mode=="gmysql")
      d_db=new SMySQL(getArg("dbname"),
		    getArg("host"),
		    getArg("socket"),
		    getArg("user"),
		    getArg("password"));
#endif
#ifdef PDNS_DOPGSQL
    else if(mode=="gpgsql")
      d_db=new SPgSQL(getArg("dbname"),
		      getArg("host"),
		      getArg("socket"),
		      getArg("user"),
		      getArg("password"));
#endif 
    else {
      L<<Logger::Error<<d_logprefix<<"Generic backend does not support database '"<<mode<<"'"<<endl;
      exit(1);
    }
      
  }
  catch(SSqlException &e) {
    L<<Logger::Error<<d_logprefix<<"Connection failed: "<<e.txtReason()<<endl;
    throw AhuException("Unable to launch "+mode+" connection: "+e.txtReason());
  }
		  
  d_noWildCardNoIDQuery=getArg("basic-query");
  d_noWildCardIDQuery=getArg("id-query");
  d_wildCardNoIDQuery=getArg("wildcard-query");
  d_wildCardIDQuery=getArg("wildcard-id-query");

  d_noWildCardANYNoIDQuery=getArg("any-query");
  d_noWildCardANYIDQuery=getArg("any-id-query");
  d_wildCardANYNoIDQuery=getArg("wildcard-any-query");
  d_wildCardANYIDQuery=getArg("wildcard-any-id-query");
  
  d_listQuery=getArg("list-query");
  L<<Logger::Warning<<d_logprefix<<"Connection succesful"<<endl;
}

gMySQLBackend::~gMySQLBackend()
{
  if(d_db)
    delete d_db;
  L<<Logger::Error<<d_logprefix<<"Closing connection"<<endl;
}

void gMySQLBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int domain_id)
{
  string format;
  char output[1024];

  d_db->setLog(arg().mustDo("query-logging"));

  string lcqname=toLower(qname);
  
  if(qtype.getCode()!=QType::ANY) {
    // qtype qname domain_id
    if(domain_id<0) {
      if(qname[0]=='%')
	format=d_wildCardNoIDQuery;
      else
	format=d_noWildCardNoIDQuery;

      snprintf(output,1023, format.c_str(),sqlEscape(qtype.getName()).c_str(), sqlEscape(lcqname).c_str());
    }
    else {
      if(qname[0]!='%')
	format=d_noWildCardIDQuery;
      else
	format=d_wildCardIDQuery;
      snprintf(output,1023, format.c_str(),sqlEscape(qtype.getName()).c_str(),sqlEscape(lcqname).c_str(),domain_id);
    }
  }
  else {
    // qtype==ANY
    // qname domain_id
    if(domain_id<0) {
      if(qname[0]=='%')
	format=d_wildCardANYNoIDQuery;
      else
	format=d_noWildCardANYNoIDQuery;

      snprintf(output,1023, format.c_str(),sqlEscape(lcqname).c_str());
    }
    else {
      if(qname[0]!='%')
	format=d_noWildCardANYIDQuery;
      else
	format=d_wildCardANYIDQuery;
      snprintf(output,1023, format.c_str(),sqlEscape(lcqname).c_str(),domain_id);
    }
  }
  DLOG(L<< "Query: '" << output << "'"<<endl);

  try {
    d_db->doQuery(output);
  }
  catch(SSqlException &e) {
    throw AhuException(e.txtReason());
  }

  d_qname=qname;

  d_qtype=qtype;
  d_count=0;
}
bool gMySQLBackend::list(int domain_id )
{
  DLOG(L<<"gMySQLBackend constructing handle for list of domain id'"<<domain_id<<"'"<<endl);

  char output[1024];
  snprintf(output,1023,d_listQuery.c_str(),domain_id);
  try {
    d_db->doQuery(output);
  }
  catch(SSqlException &e) {
    throw AhuException("gMySQLBackend list query: "+e.txtReason());
  }

  d_qname="";
  d_count=0;
  return true;
}

bool gMySQLBackend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **ddb)
{
  // check if we know the ip/ns couple in the database
  for(vector<DNSResourceRecord>::const_iterator i=nsset.begin();i!=nsset.end();++i) {
    try {
      d_db->doQuery(("select account from supermasters where ip='"+sqlEscape(ip)+"' and nameserver='"+sqlEscape(i->content)+"'"),
		    d_result);
    }
    catch (SSqlException &e) {
      throw AhuException("gMySQLBackend unable to search for a domain: "+e.txtReason());
    }

    if(!d_result.empty()) {
      *account=d_result[0][0];
      *ddb=this;
      return true;
    }
  }
  return false;
}

bool gMySQLBackend::createSlaveDomain(const string &ip, const string &domain, const string &account)
{
  try {
    d_db->doQuery(("insert into domains (type,name,master,account) values('SLAVE','"+
		   sqlEscape(domain)+"','"+
		   sqlEscape(ip)+"','"+sqlEscape(account)+"')"));
  }
  catch(SSqlException &e) {
    throw AhuException("Database error trying to insert new slave '"+domain+"': "+ e.txtReason());
  }
  return true;
}


bool gMySQLBackend::get(DNSResourceRecord &r)
{
  // L << "gMySQLBackend get() was called for "<<qtype.getName() << " record: ";
  SSql::row_t row;
  if(d_db->getRow(row)) {
    r.content=row[0];
    r.ttl=atol(row[1].c_str());
    r.priority=atol(row[2].c_str());
    if(!d_qname.empty())
      r.qname=d_qname;
    else
      r.qname=row[5];
    r.qtype=row[3];
    
    r.domain_id=atoi(row[4].c_str());
    return true;
  }
  
  return false;
}

bool gMySQLBackend::feedRecord(const DNSResourceRecord &r)
{
  ostringstream os;
  
  os<<"insert into records (content,ttl,prio,type,domain_id,name) values ('"<<
    sqlEscape(r.content)<<"', "<<
    r.ttl<<", "<<
    r.priority<<", '"<<sqlEscape(r.qtype.getName())<<"', "<<
    r.domain_id<<
    ", '"<<sqlEscape(r.qname)<<"')";
  
  //  L<<Logger::Error<<"Trying: '"<<os.str()<<"'"<<endl;

  try {
    d_db->doQuery(os.str());
  }
  catch (SSqlException &e) {
    throw AhuException(e.txtReason());
  }
  return true; // XXX FIXME this API should not return 'true' I think -ahu 
}

bool gMySQLBackend::startTransaction(const string &domain, int domain_id)
{
  try {
    d_db->doQuery("begin");
    d_db->doQuery("delete from records where domain_id="+itoa(domain_id));
  }
  catch (SSqlException &e) {
    throw AhuException("Database failed to start transaction: "+e.txtReason());
  }

  return true;
}

bool gMySQLBackend::commitTransaction()
{
  try {
    d_db->doQuery("commit");
  }
  catch (SSqlException &e) {
    throw AhuException("Database failed to commit transaction: "+e.txtReason());
  }
  return true;
}

bool gMySQLBackend::abortTransaction()
{
  try {
    d_db->doQuery("rollback");
  }
  catch(SSqlException &e) {
    throw AhuException("MySQL failed to abort transaction: "+string(e.txtReason()));
  }
  return true;
}


class gMySQLFactory : public BackendFactory
{
public:
  gMySQLFactory(const string &mode) : BackendFactory(mode),d_mode(mode) {}
  
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
    BackendMakers().report(new gMySQLFactory("gpgsql2"));
    L<<Logger::Warning<<"This is module gmysqlbackend.so reporting"<<endl;
  }
};
static gMySQLLoader gmysqlloader;
