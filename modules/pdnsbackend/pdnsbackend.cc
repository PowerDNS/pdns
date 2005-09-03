// $Id$ 

#include <string>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>

using namespace std;

#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>

#include "pdnsbackend.hh"

static string backendName="[PdnsBackend]";

string PdnsBackend::sqlEscape(const string &name)
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

PdnsBackend::PdnsBackend(const string &suffix)
   : d_result(NULL)
{
   mysql_init(&d_database);
   d_suffix=suffix;
   MYSQL* theDatabase = mysql_real_connect
      (
	 &d_database,
	 arg()["pdns-"+suffix+"host"].c_str(),
	 arg()["pdns-"+suffix+"user"].c_str(),
	 arg()["pdns-"+suffix+"password"].c_str(),
	 arg()["pdns-"+suffix+"dbname"].c_str(),
	 0,
	 arg()["pdns-"+suffix+"socket"].empty() ? NULL : arg()["pdns-"+suffix+"socket"].c_str(),
	 0
      );

   if (theDatabase == NULL) {
      throw(AhuException("mysql_real_connect failed: "+string(mysql_error(&d_database))));
   }
   
   L << Logger::Warning << backendName << " MySQL connection succeeded" << endl;
}

PdnsBackend::~PdnsBackend()
{
   mysql_close(&d_database);
}

void PdnsBackend::Query(const string& inQuery)
{
   //cout << "PdnsBackend::Query: " << inQuery << endl;

   //
   // Cleanup the previous result, if it exists.
   //

   if (d_result != NULL) {
      mysql_free_result(d_result);
      d_result = NULL;
   }
   
   if (mysql_query(&d_database, inQuery.c_str()) != 0) { 
      throw AhuException("mysql_query failed");
   }
  
   d_result = mysql_use_result(&d_database);
   if (d_result == NULL) {
      throw AhuException("mysql_use_result failed");
   }
}

void PdnsBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int zoneId )
{
  string query;

  //cout << "PdnsBackend::lookup" << endl;
  
  // suport wildcard searches
  
  if (qname[0]!='%') {
     query="select r.Content,r.TimeToLive,r.Priority,r.Type,r.ZoneId,r.Name,r.ChangeDate from Records r,Zones z where r.Name='";
  } else {
     query="select r.Content,r.TimeToLive,r.Priority,r.Type,r.ZoneId,r.Name,r.ChangeDate from Records r,Zones z where r.Name like '";
  }

  if (qname.find_first_of("'\\")!=string::npos)
    query+=sqlEscape(qname);
  else
    query+=qname;  

  query+="'";
  if (qtype.getCode()!=255) {  // ANY
    query+=" and r.Type='";
    query+=qtype.getName();
    query+="'";
  }

  if (zoneId>0) {
    query+=" and r.ZoneId=";
    ostringstream o;
    o<<zoneId;
    query+=o.str();
  }
  
  // XXX Make this optional, because it adds an extra load to the db
  query += " and r.Active <> 0 and r.ZoneId = z.Id and z.Active <> 0";
  
  DLOG(L<< backendName<<" Query: '" << query << "'"<<endl);

  this->Query(query);
}

bool PdnsBackend::list(const string &target, int inZoneId)
{
   //cout << "PdnsBackend::list" << endl;

   ostringstream theQuery;
   
   theQuery << "select Content,TimeToLive,Priority,Type,ZoneId,Name,ChangeDate from Records where ZoneId = ";
   theQuery << inZoneId;
   
   this->Query(theQuery.str());
   return true;
}

bool PdnsBackend::getSOA(const string& inZoneName, SOAData& outSoaData)
{
   bool theResult = false;
   MYSQL_ROW theRow = NULL;

   //cout << "PdnsBackend::getSOA" << endl;

   ostringstream o;
   o << "select Id,Hostmaster,Serial from Zones where Active = 1 and Name = '" << sqlEscape(inZoneName) << "'";

   this->Query(o.str());
      
   theRow = mysql_fetch_row(d_result);
   if (theRow != NULL)
   {
      outSoaData.domain_id = atoi(theRow[0]);
      
      outSoaData.nameserver = arg()["default-soa-name"];
      outSoaData.hostmaster = theRow[1];
      outSoaData.serial = atoi(theRow[2]);
      
      outSoaData.refresh = arg()["pdns-"+d_suffix+"soa-refresh"].empty() ? 10800 : atoi(arg()["pdns-"+d_suffix+"soa-refresh"].c_str());
      outSoaData.retry = 3600;
      outSoaData.expire = 604800;
      outSoaData.default_ttl = 40000;
      outSoaData.db = this;
      
      theResult = true;
   }
   
   return theResult;
}

//! For the dynamic loader
DNSBackend *PdnsBackend::maker()
{
  DNSBackend *tmp;
  try
    {
      tmp=new PdnsBackend;
    }
  catch(...)
    {
      return 0;
    }
  return tmp;
}

bool PdnsBackend::get(DNSResourceRecord& r)
{
   bool theResult = false;

   //cout << "PdnsBackend::get" << endl;

   MYSQL_ROW row;
   
   row = mysql_fetch_row(d_result);
   if (row != NULL)
   {
      r.content=row[0];  // content
  
      if(!row[1])  // ttl
	 r.ttl=0;
      else
	 r.ttl=atoi(row[1]);
        
      if(row[2])
	 r.priority=atoi(row[2]);;

      r.qname=row[5];
   
      r.qtype=(const char *)row[3];
      
      r.domain_id=atoi(row[4]);
      if(!row[6])
	 r.last_modified=0;
      else
	 r.last_modified=atoi(row[6]);
   
      theResult = true;
   }

   return theResult;
}

class PDNSFactory : public BackendFactory
{
   public:

      PDNSFactory() : BackendFactory("pdns") {}
  
      void declareArguments(const string &suffix="")
      {
	 declare(suffix,"dbname","Pdns backend database name to connect to","powerdns");
	 declare(suffix,"user","Pdns backend user to connect as","powerdns");
	 declare(suffix,"host","Pdns backend host to connect to","");
	 declare(suffix,"password","Pdns backend password to connect with","");
	 declare(suffix,"socket","Pdns backend socket to connect to","");
	 declare(suffix,"soa-refresh","Pdns SOA refresh in seconds","");
      }
      
      DNSBackend *make(const string &suffix="")
      {
	 return new PdnsBackend(suffix);
      }
};


//! Magic class that is activated when the dynamic library is loaded
class PdnsBeLoader
{
   public:

      PdnsBeLoader()
      {
	 BackendMakers().report(new PDNSFactory);
	 L<<Logger::Notice<<backendName<<" This is the pdns module version "VERSION" ("__DATE__", "__TIME__") reporting"<<endl;
      }
};

static PdnsBeLoader pdnsbeloader;
