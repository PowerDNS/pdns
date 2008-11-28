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

void PdnsBackend::Execute(const string& inStatement)
{
   //
   // Cleanup the previous result, if it exists.
   //

   if (d_result != NULL) {
      mysql_free_result(d_result);
      d_result = NULL;
   }
   
   if (mysql_query(&d_database, inStatement.c_str()) != 0) {
      throw AhuException(string("mysql_query failed")+string(mysql_error(&d_database)));
   }
}

void PdnsBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int zoneId )
{
  string query;

  //cout << "PdnsBackend::lookup" << endl;
  
  // suport wildcard searches
  
  if (qname[0]!='%') {
     query  ="select r.Content,r.TimeToLive,r.Priority,r.Type,r.ZoneId,r.Name,r.ChangeDate ";
     query +="from Records r left join Zones z on r.ZoneId = z.Id where r.Name='";
  } else {
     query  ="select r.Content,r.TimeToLive,r.Priority,r.Type,r.ZoneId,r.Name,r.ChangeDate ";
     query +="from Records r left join Zones z on r.ZoneId = z.Id where r.Name like '";
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
  query += " and r.Active <> 0 and z.Active <> 0";
  
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

bool PdnsBackend::getSOA(const string& inZoneName, SOAData& outSoaData, DNSPacket*)
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

bool PdnsBackend::isMaster(const string &name, const string &ip)
{
   bool theResult = false;
   MYSQL_ROW theRow = NULL;
   string master;
   
   ostringstream o;
   o << "select Master from Zones where Master != '' and Name='"<<sqlEscape(name)<<"'";
   
   this->Query(o.str());
   
   theRow = mysql_fetch_row(d_result);
   if (theRow != NULL)
   {
      master = theRow[0];
   }
   
   if(master == ip)
      theResult = true;
   
   return theResult;
}

void PdnsBackend::getUnfreshSlaveInfos(vector<DomainInfo>* unfreshDomains)
{
   MYSQL_ROW theRow = NULL;
   
   string o = "select Id,Name,Master,UNIX_TIMESTAMP(ChangeDate) from Zones where Master != ''";
   
   this->Query(o);
   
   vector<DomainInfo>allSlaves;
   while((theRow = mysql_fetch_row(d_result)) != NULL) {
      DomainInfo di;
      
      di.id         = atol(theRow[0]);
      di.zone       = theRow[1];
      stringtok(di.masters, theRow[2], ", \t");
      di.last_check = atol(theRow[3]);
      di.backend    = this;
      di.kind       = DomainInfo::Slave;
      allSlaves.push_back(di);
   }
   
   for(vector<DomainInfo>::iterator i=allSlaves.begin(); i!=allSlaves.end();i++) {
      SOAData sd;
      sd.serial=0;
      sd.refresh=0;
      getSOA(i->zone,sd);
      if((time_t)(i->last_check+sd.refresh) < time(0)) {
         i->serial=sd.serial;
         unfreshDomains->push_back(*i);
      }
   }
}

bool PdnsBackend::getDomainInfo(const string &domain, DomainInfo &di)
{
   bool theResult = false;
   MYSQL_ROW theRow = NULL;
   vector<string> masters;
   
   ostringstream o;
   o << "select Id,Name,Master,UNIX_TIMESTAMP(ChangeDate) from Zones WHERE Name='" << sqlEscape(domain) << "'";
   
   this->Query(o.str());
   
   theRow = mysql_fetch_row(d_result);
   if (theRow != NULL)
   {
      di.id         = atol(theRow[0]);
      di.zone       = theRow[1];
      di.last_check = atol(theRow[3]);
      di.backend    = this;
      
      /* We have to store record in local variabel... theRow[2] == NULL makes it empty in di.master = theRow[2]???? */
      if(theRow[2] != NULL)
	 stringtok(masters, theRow[2], " ,\t");
      
      if (masters.empty())
      {
         di.kind = DomainInfo::Native;
      }
      else
      {
         di.serial = 0;
         try {
            SOAData sd;
            if(!getSOA(domain,sd))
               L<<Logger::Notice<<"No serial for '"<<domain<<"' found - zone is missing?"<<endl;
            di.serial = sd.serial;
         }
         catch (AhuException &ae) {
            L<<Logger::Error<<"Error retrieving serial for '"<<domain<<"': "<<ae.reason<<endl;
         }
         
         di.kind   = DomainInfo::Slave;
         di.masters = masters;
      }
      
      theResult = true;
   }
      
   return theResult;
}

bool PdnsBackend::startTransaction(const string &qname, int domain_id)
{
   ostringstream o;
   o << "delete from Records where ZoneId=" << domain_id;

   this->Execute("begin");
   this->Execute(o.str());
   
   d_axfrcount = 0;
   
   return true;
}

bool PdnsBackend::feedRecord(const DNSResourceRecord &rr)
{    
   int qcode = rr.qtype.getCode();
   
   /* Check max records to transfer except for SOA and NS records */
   if((qcode != QType::SOA) && (qcode != QType::NS))
   {
      if (d_axfrcount == atol(arg()["pdns-"+d_suffix+"max-slave-records"].c_str())  - 1)
      {
         L<<Logger::Warning<<backendName<<" Maximal AXFR records reached: "<<arg()["pdns-"+d_suffix+"max-slave-records"]
                           <<". Skipping rest of records"<<endl;
      }
      
      if (d_axfrcount >= atol(arg()["pdns-"+d_suffix+"max-slave-records"].c_str())) {
         return true;
      }
      
      d_axfrcount++; // increase AXFR count for pdns-max-slave-records
   }
   
   /* SOA is not be feeded into Records.. update serial instead */
   if(qcode == QType::SOA)
   {
      string::size_type emailpos = rr.content.find(" ", 0) + 1;
      string::size_type serialpos = rr.content.find(" ", emailpos) + 1;
      string::size_type other = rr.content.find(" ", serialpos);
      string serial = rr.content.substr(serialpos, other - serialpos);
      
      ostringstream q;
      q << "update Zones set Serial=" << serial << " where Id=" << rr.domain_id;
      
      this->Execute(q.str());
      
      return true;
   }
   
   ostringstream o;
   o << "insert into Records (ZoneId, Name, Type, Content, TimeToLive, Priority, Flags, Active) values ("
     << rr.domain_id << ","
     << "'" << toLower(sqlEscape(rr.qname)).c_str() << "',"
     << "'" << sqlEscape(rr.qtype.getName()).c_str() << "',"
     << "'" << sqlEscape(rr.content).c_str() << "',"
     << rr.ttl << ","
     << rr.priority << ","
     << "4" << ","
     << "1)";
   
   this->Execute(o.str());
   
   return true;
}

bool PdnsBackend::commitTransaction()
{
	 this->Execute("commit");
	 
	 d_axfrcount = 0;
	 
	 return true;
}

bool PdnsBackend::abortTransaction()
{
	 this->Execute("rollback");
	 
	 d_axfrcount = 0;
	 
	 return true;
}

void PdnsBackend::setFresh(u_int32_t domain_id)
{
   ostringstream o;
   o << "update Zones set ChangeDate = NOW() where Id=" << domain_id;
   
   this->Execute(o.str());
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
	 declare(suffix,"max-slave-records","Pdns backend maximal records to transfer", "100");
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
