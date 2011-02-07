// $Id$ 
#include <string>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>

#include "pdns/namespaces.hh"

#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include "mysqlcbackend.hh"
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>

static string backendName="[MySQLbackend]";

string MySQLBackend::sqlEscape(const string &name)
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

MySQLBackend::MySQLBackend(const string &suffix)
{
  mysql_init(&db);
  L<<Logger::Error<<backendName<<" *** THIS BACKEND IS DEPRECATED - USE GMYSQL! ***"<<endl;
  setArgPrefix("mysql"+suffix);
  if (!mysql_real_connect(&db,getArg("host").c_str(),
        		  getArg("user").c_str(),
        		  getArg("password").c_str(),
        		  getArg("dbname").c_str(),
        		  0,
        		  getArg("socket").empty() ? 
        		  NULL : getArg("socket").c_str(),0)) {
    L<<Logger::Error<<backendName<<" Failed to connect to database: Error: "<<mysql_error(&db)<<endl;
    throw(AhuException(backendName+string(" Failed to connect to database: Error: ")+mysql_error(&db)));
  }
  d_table=getArg("table");
  L<<Logger::Warning<<backendName<<" MySQL connection succeeded"<<endl;
}

MySQLBackend::~MySQLBackend()
{
  L<<Logger::Warning<<backendName<<" MySQL connection closed"<<endl;
  mysql_close(&db);
}

void MySQLBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int zoneId )
{
  string query;
  
  // suport wildcard searches
  if(qname[0]!='%')
    query="select content,ttl,prio,type,domain_id,name,change_date from "+d_table+" where name='";
  else
    query="select content,ttl,prio,type,domain_id,name,change_date from "+d_table+" where name like '";

  if(qname.find_first_of("'\\")!=string::npos)
    query+=sqlEscape(qname);
  else
    query+=qname;

  query+="'";
  if(qtype.getCode()!=255) {  // ANY
    query+=" and type='";
    query+=qtype.getName();
    query+="'";
  }

  if(zoneId>0) {
    query+=" and domain_id=";
    ostringstream o;
    o<<zoneId;
    query+=o.str();
  }
    
  DLOG(L<< backendName<<" Query: '" << query << "'"<<endl);

  if(arg().mustDo("query-logging"))
    L<<Logger::Error<<"Query: '"<<query<<"'"<<endl;

  if(mysql_query(&db,query.c_str())) 
    throw AhuException("Failed to execute mysql_query '"+query+"'. Error: "+string(mysql_error(&db)));
    
  if(!(d_res = mysql_use_result(&db))) 
    throw AhuException("mysql_use_result failed. Error: "+string(mysql_error(&db)));
 
  d_qname=qname;
  d_qtype=qtype;
}

bool MySQLBackend::list(const string &target, int domain_id )
{
  DLOG(L<<backendName<<" MySQLBackend constructing handle for list of domain id '"<<domain_id<<"'"<<endl);

  ostringstream o;
  o<<"select content,ttl,prio,type,domain_id,name,change_date from "+d_table+" where domain_id="<<domain_id;
  
  if(mysql_query(&db, o.str().c_str()))
    throw AhuException("Failed to execute mysql_query '"+o.str()+"'. Error: "+string(mysql_error(&db)));
  
  if(!(d_res=mysql_use_result(&db))) 
    throw AhuException("mysql_use_result failed. Error: "+string(mysql_error(&db)));

  d_qname=""; // this tells 'get' what to do
  return true;
}

bool MySQLBackend::get(DNSResourceRecord &r)
{
  //  L << "MySQLBackend get() was called for "<<qtype.getName() << " record: "<<qname<<endl;
  MYSQL_ROW row;

  if(!(row = mysql_fetch_row(d_res))) { // end
      mysql_free_result(d_res);
    return false;
  }
  
  r.content=row[0];  // content
  
  if(!row[1])  // ttl
    r.ttl=0;
  else
    r.ttl=atoi(row[1]);
  
  
  if(row[2])
    r.priority=atoi(row[2]);;
  
  if(!d_qname.empty()) // use this to distinguish between select with 'name' field (list()) and one without
    r.qname=d_qname;
  else
    r.qname=row[5];
  
  r.qtype=(const char *)row[3];
  
  r.domain_id=atoi(row[4]);
  if(!row[6])
    r.last_modified=0;
  else
    r.last_modified=atoi(row[6]);
  
      //L << "MySQLBackend get() returning a rr"<<endl;

  return true;
}

class MySQLFactory : public BackendFactory
{
public:
  MySQLFactory() : BackendFactory("mysql") {}
  
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"dbname","Pdns backend database name to connect to","powerdns");
    declare(suffix,"user","Pdns backend user to connect as","powerdns");
    declare(suffix,"host","Pdns backend host to connect to","");
    declare(suffix,"password","Pdns backend password to connect with","");
    declare(suffix,"socket","Pdns backend socket to connect to","");
    declare(suffix,"table","Name of table to use","records");
  }
  
  DNSBackend *make(const string &suffix="")
  {
    return new MySQLBackend(suffix);
  }
};


//! Magic class that is activated when the dynamic library is loaded
class Loader
{
public:
  //! This reports us to the main UeberBackend class
  Loader()
  {
    BackendMakers().report(new MySQLFactory);
    L<<Logger::Notice<<backendName<<" This is the mysql module version "VERSION" ("__DATE__", "__TIME__") reporting"<<endl;

  }
};
static Loader loader;
