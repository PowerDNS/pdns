// $Id$ 
#ifdef WIN32
# pragma warning ( disable: 4786 )
#endif // WIN32

#include <string>
#include <map>

using namespace std;

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "gsqlbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ueberbackend.hh"
#include "pdns/ahuexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include <boost/algorithm/string.hpp>
#include <sstream>
using namespace boost;

void GSQLBackend::setNotified(uint32_t domain_id, uint32_t serial)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,
	   d_UpdateSerialOfZoneQuery.c_str(),
	   serial, domain_id);

  try {
    d_db->doCommand(output);
  }
  catch(SSqlException &e) {
    throw AhuException("GSQLBackend unable to refresh domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
}

void GSQLBackend::setFresh(uint32_t domain_id)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,d_UpdateLastCheckofZoneQuery.c_str(),
	   time(0),
	   domain_id);

  try {
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to refresh domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
}

bool GSQLBackend::isMaster(const string &domain, const string &ip)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,
	   d_MasterOfDomainsZoneQuery.c_str(),
	   sqlEscape(domain).c_str());
  try {
    d_db->doQuery(output, d_result);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to retrieve list of master domains: "+e.txtReason());
  }

  if(d_result.empty())
    return 0;
  
  return !strcmp(ip.c_str(),d_result[0][0].c_str());
}

bool GSQLBackend::getDomainInfo(const string &domain, DomainInfo &di)
{
  /* list all domains that need refreshing for which we are slave, and insert into SlaveDomain:
     id,name,master IP,serial */
  char output[1024];
  snprintf(output,sizeof(output)-1,d_InfoOfDomainsZoneQuery.c_str(),
	   sqlEscape(domain).c_str());
  try {
    d_db->doQuery(output,d_result);
  }
  catch(SSqlException &e) {
    throw AhuException("GSQLBackend unable to retrieve information about a domain: "+e.txtReason());
  }

  int numanswers=d_result.size();
  if(!numanswers)
    return false;
  
  di.id=atol(d_result[0][0].c_str());
  di.zone=d_result[0][1];
  stringtok(di.masters, d_result[0][2], " ,\t");
  di.last_check=atol(d_result[0][3].c_str());
  di.backend=this;
  
  string type=d_result[0][5];
  if(iequals(type,"SLAVE")) {
    di.serial=0;
    try {
      SOAData sd;
      if(!getSOA(domain,sd)) 
	L<<Logger::Notice<<"No serial for '"<<domain<<"' found - zone is missing?"<<endl;
      else
	di.serial=sd.serial;
    }
    catch(AhuException &ae){
      L<<Logger::Error<<"Error retrieving serial for '"<<domain<<"': "<<ae.reason<<endl;
    }
    
    di.kind=DomainInfo::Slave;
  }
  else if(iequals(type,"MASTER"))
    di.kind=DomainInfo::Slave;
  else 
    di.kind=DomainInfo::Native;
  
  return true;
}

void GSQLBackend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  /* list all domains that need refreshing for which we are slave, and insert into SlaveDomain:
     id,name,master IP,serial */
  char output[1024];
  snprintf(output,sizeof(output)-1,d_InfoOfAllSlaveDomainsQuery.c_str());

  try {
    d_db->doQuery(output,d_result);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to retrieve list of slave domains: "+e.txtReason());
  }

  vector<DomainInfo>allSlaves;
  int numanswers=d_result.size();
  for(int n=0;n<numanswers;++n) { // id,name,master,last_check
    DomainInfo sd;
    sd.id=atol(d_result[n][0].c_str());
    sd.zone=d_result[n][1];
    stringtok(sd.masters, d_result[n][2], ", \t");
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

void GSQLBackend::getUpdatedMasters(vector<DomainInfo> *updatedDomains)
{
  /* list all domains that need notifications for which we are master, and insert into updatedDomains
     id,name,master IP,serial */
  char output[1024];
  snprintf(output, sizeof(output)-1, d_InfoOfAllMasterDomainsQuery.c_str());

  try {
    d_db->doQuery(output,d_result);
  }
  catch(SSqlException &e) {
    throw AhuException("GSQLBackend unable to retrieve list of master domains: "+e.txtReason());
  }

  vector<DomainInfo> allMasters;
  int numanswers=d_result.size();
  for(int n=0;n<numanswers;++n) { // id,name,master,last_check
    DomainInfo sd;
    sd.id=atol(d_result[n][0].c_str());
    sd.zone=d_result[n][1];
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


string GSQLBackend::sqlEscape(const string &name)
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


GSQLBackend::GSQLBackend(const string &mode, const string &suffix)
{
  setArgPrefix(mode+suffix);
  d_db=0;
  d_logprefix="["+mode+"Backend"+suffix+"] ";
		  
  d_noWildCardNoIDQuery=getArg("basic-query");
  d_noWildCardIDQuery=getArg("id-query");
  d_wildCardNoIDQuery=getArg("wildcard-query");
  d_wildCardIDQuery=getArg("wildcard-id-query");

  d_noWildCardANYNoIDQuery=getArg("any-query");
  d_noWildCardANYIDQuery=getArg("any-id-query");
  d_wildCardANYNoIDQuery=getArg("wildcard-any-query");
  d_wildCardANYIDQuery=getArg("wildcard-any-id-query");
  
  d_listQuery=getArg("list-query");

  d_MasterOfDomainsZoneQuery=getArg("master-zone-query");
  d_InfoOfDomainsZoneQuery=getArg("info-zone-query");
  d_InfoOfAllSlaveDomainsQuery=getArg("info-all-slaves-query");
  d_SuperMasterInfoQuery=getArg("supermaster-query");
  d_InsertSlaveZoneQuery=getArg("insert-slave-query");
  d_InsertRecordQuery=getArg("insert-record-query");
  d_UpdateSerialOfZoneQuery=getArg("update-serial-query");
  d_UpdateLastCheckofZoneQuery=getArg("update-lastcheck-query");
  d_InfoOfAllMasterDomainsQuery=getArg("info-all-master-query");
  d_DeleteZoneQuery=getArg("delete-zone-query");
}


void GSQLBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int domain_id)
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

      snprintf(output,sizeof(output)-1, format.c_str(),sqlEscape(qtype.getName()).c_str(), sqlEscape(lcqname).c_str());
    }
    else {
      if(qname[0]!='%')
	format=d_noWildCardIDQuery;
      else
	format=d_wildCardIDQuery;
      snprintf(output,sizeof(output)-1, format.c_str(),sqlEscape(qtype.getName()).c_str(),sqlEscape(lcqname).c_str(),domain_id);
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

      snprintf(output,sizeof(output)-1, format.c_str(),sqlEscape(lcqname).c_str());
    }
    else {
      if(qname[0]!='%')
	format=d_noWildCardANYIDQuery;
      else
	format=d_wildCardANYIDQuery;
      snprintf(output,sizeof(output)-1, format.c_str(),sqlEscape(lcqname).c_str(),domain_id);
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
bool GSQLBackend::list(const string &target, int domain_id )
{
  DLOG(L<<"GSQLBackend constructing handle for list of domain id'"<<domain_id<<"'"<<endl);

  char output[1024];
  snprintf(output,sizeof(output)-1,d_listQuery.c_str(),domain_id);
  try {
    d_db->doQuery(output);
  }
  catch(SSqlException &e) {
    throw AhuException("GSQLBackend list query: "+e.txtReason());
  }

  d_qname="";
  d_count=0;
  return true;
}

bool GSQLBackend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **ddb)
{
  string format;
  char output[1024];
  format = d_SuperMasterInfoQuery;
  // check if we know the ip/ns couple in the database
  for(vector<DNSResourceRecord>::const_iterator i=nsset.begin();i!=nsset.end();++i) {
    try {
      snprintf(output,sizeof(output)-1,format.c_str(),sqlEscape(ip).c_str(),sqlEscape(i->content).c_str());
      d_db->doQuery(output, d_result);
    }
    catch (SSqlException &e) {
      throw AhuException("GSQLBackend unable to search for a domain: "+e.txtReason());
    }

    if(!d_result.empty()) {
      *account=d_result[0][0];
      *ddb=this;
      return true;
    }
  }
  return false;
}

bool GSQLBackend::createSlaveDomain(const string &ip, const string &domain, const string &account)
{
  string format;
  char output[1024];
  format = d_InsertSlaveZoneQuery;
  snprintf(output,sizeof(output)-1,format.c_str(),sqlEscape(domain).c_str(),sqlEscape(ip).c_str(),sqlEscape(account).c_str());
  try {
    d_db->doCommand(output);
  }
  catch(SSqlException &e) {
    throw AhuException("Database error trying to insert new slave '"+domain+"': "+ e.txtReason());
  }
  return true;
}


bool GSQLBackend::get(DNSResourceRecord &r)
{
  // L << "GSQLBackend get() was called for "<<qtype.getName() << " record: ";
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
    r.last_modified=0;
    
    r.domain_id=atoi(row[4].c_str());
    return true;
  }
  
  return false;
}

bool GSQLBackend::feedRecord(const DNSResourceRecord &r)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,d_InsertRecordQuery.c_str(),
	   sqlEscape(r.content).c_str(),
	   r.ttl, r.priority,
	   sqlEscape(r.qtype.getName()).c_str(),
	   r.domain_id, toLower(sqlEscape(r.qname)).c_str()); 
  try {
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw AhuException(e.txtReason());
  }
  return true; // XXX FIXME this API should not return 'true' I think -ahu 
}

bool GSQLBackend::startTransaction(const string &domain, int domain_id)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,d_DeleteZoneQuery.c_str(),domain_id);
  try {
    d_db->doCommand("begin");
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw AhuException("Database failed to start transaction: "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::commitTransaction()
{
  try {
    d_db->doCommand("commit");
  }
  catch (SSqlException &e) {
    throw AhuException("Database failed to commit transaction: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::abortTransaction()
{
  try {
    d_db->doCommand("rollback");
  }
  catch(SSqlException &e) {
    throw AhuException("MySQL failed to abort transaction: "+string(e.txtReason()));
  }
  return true;
}

