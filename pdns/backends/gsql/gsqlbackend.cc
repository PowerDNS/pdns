/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

// $Id$ 
#ifdef WIN32
# pragma warning ( disable: 4786 )
#endif // WIN32

#include <string>
#include <map>

#include "namespaces.hh"

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
#include <boost/foreach.hpp>
#include <boost/format.hpp>



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

  // we can have multiple masters separated by commas
  vector<string> masters;
  stringtok(masters, d_result[0][0], " ,\t");
  for(vector<string>::const_iterator iter=masters.begin(); iter != masters.end(); ++iter) {
     // we can also have masters with a port specified (which we ignore here)
     ServiceTuple st;
     parseService(*iter, st);
     if (!strcmp(ip.c_str(), st.host.c_str())) {
         return 1;
     }
  }

 // if no masters matched then this is not a master
  return 0;  
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
  if(pdns_iequals(type,"SLAVE")) {
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
  else if(pdns_iequals(type,"MASTER"))
    di.kind=DomainInfo::Master;
  else 
    di.kind=DomainInfo::Native;
  
  return true;
}

void GSQLBackend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  /* list all domains that need refreshing for which we are slave, and insert into SlaveDomain:
     id,name,master IP,serial */
  try {
    d_db->doQuery(d_InfoOfAllSlaveDomainsQuery, d_result);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to retrieve list of slave domains: "+e.txtReason());
  }

  vector<DomainInfo> allSlaves;
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
  try {
    d_db->doQuery(d_InfoOfAllMasterDomainsQuery,d_result);
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
	
  try
  {
    d_dnssecQueries = mustDo("dnssec");
  }
  catch (ArgException e)
  {
    d_dnssecQueries = false;
  }

  string authswitch = d_dnssecQueries ? "-auth" : "";	  
  d_noWildCardNoIDQuery=getArg("basic-query"+authswitch);
  d_noWildCardIDQuery=getArg("id-query"+authswitch);
  d_wildCardNoIDQuery=getArg("wildcard-query"+authswitch);
  d_wildCardIDQuery=getArg("wildcard-id-query"+authswitch);

  d_noWildCardANYNoIDQuery=getArg("any-query"+authswitch);
  d_noWildCardANYIDQuery=getArg("any-id-query"+authswitch);
  d_wildCardANYNoIDQuery=getArg("wildcard-any-query"+authswitch);
  d_wildCardANYIDQuery=getArg("wildcard-any-id-query"+authswitch);
  
  d_listQuery=getArg("list-query"+authswitch);

  d_MasterOfDomainsZoneQuery=getArg("master-zone-query");
  d_InfoOfDomainsZoneQuery=getArg("info-zone-query");
  d_InfoOfAllSlaveDomainsQuery=getArg("info-all-slaves-query");
  d_SuperMasterInfoQuery=getArg("supermaster-query");
  d_InsertSlaveZoneQuery=getArg("insert-slave-query");
  d_InsertRecordQuery=getArg("insert-record-query"+authswitch);
  d_UpdateSerialOfZoneQuery=getArg("update-serial-query");
  d_UpdateLastCheckofZoneQuery=getArg("update-lastcheck-query");
  d_ZoneLastChangeQuery=getArg("zone-lastchange-query");
  d_InfoOfAllMasterDomainsQuery=getArg("info-all-master-query");
  d_DeleteZoneQuery=getArg("delete-zone-query");
  d_getAllDomainsQuery=getArg("get-all-domains-query");
  
  if (d_dnssecQueries)
  {
    d_firstOrderQuery = getArg("get-order-first-query");
    d_beforeOrderQuery = getArg("get-order-before-query");
    d_afterOrderQuery = getArg("get-order-after-query");
    d_lastOrderQuery = getArg("get-order-last-query");
    d_setOrderAuthQuery = getArg("set-order-and-auth-query");
    
    d_AddDomainKeyQuery = getArg("add-domain-key-query");
    d_ListDomainKeysQuery = getArg("list-domain-keys-query");
    
    d_GetDomainMetadataQuery = getArg("get-domain-metadata-query");
    d_ClearDomainMetadataQuery = getArg("clear-domain-metadata-query");
    d_SetDomainMetadataQuery = getArg("set-domain-metadata-query");
    
    d_ActivateDomainKeyQuery = getArg("activate-domain-key-query");
    d_DeactivateDomainKeyQuery = getArg("deactivate-domain-key-query");
    d_RemoveDomainKeyQuery = getArg("remove-domain-key-query");
    
    d_getTSIGKeyQuery = getArg("get-tsig-key-query");
  }
}

bool GSQLBackend::updateDNSSECOrderAndAuth(uint32_t domain_id, const std::string& zonename, const std::string& qname, bool auth)
{
  if(!d_dnssecQueries)
    return false;
  string ins=toLower(labelReverse(makeRelative(qname, zonename)));
  return this->updateDNSSECOrderAndAuthAbsolute(domain_id, qname, ins, auth);
}

bool GSQLBackend::updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];
  // ordername='%s',auth=%d where name='%s' and domain_id='%d'
  
  snprintf(output, sizeof(output)-1, d_setOrderAuthQuery.c_str(), sqlEscape(ordername).c_str(), auth, sqlEscape(qname).c_str(), domain_id);
//  cerr<<"sql: '"<<output<<"'\n";
  
  d_db->doCommand(output);
  return true;
}

bool GSQLBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)
{
  if(!d_dnssecQueries)
    return false;
  // cerr<<"gsql before/after called for id="<<id<<", qname='"<<qname<<"'"<<endl;
  unhashed.clear(); before.clear(); after.clear();
  string lcqname=toLower(qname);
  
  SSql::row_t row;

  char output[1024];

  snprintf(output, sizeof(output)-1, d_afterOrderQuery.c_str(), sqlEscape(lcqname).c_str(), id);
  
  d_db->doQuery(output);
  while(d_db->getRow(row)) {
    after=row[0];
  }

  if(after.empty() && !lcqname.empty()) {
    snprintf(output, sizeof(output)-1, d_firstOrderQuery.c_str(), id);
  
    d_db->doQuery(output);
    while(d_db->getRow(row)) {
      after=row[0];
    }
  }

  snprintf(output, sizeof(output)-1, d_beforeOrderQuery.c_str(), sqlEscape(lcqname).c_str(), id);
  d_db->doQuery(output);
  while(d_db->getRow(row)) {
    before=row[0];
    unhashed=row[1];
  }
  
  if(! unhashed.empty())
  {
    // cerr<<"unhashed="<<unhashed<<",before="<<before<<", after="<<after<<endl;
    return true;
  }

  snprintf(output, sizeof(output)-1, d_lastOrderQuery.c_str(), id);
  d_db->doQuery(output);
  while(d_db->getRow(row)) {
    before=row[0];
    unhashed=row[1];
  }

  return true;
}

int GSQLBackend::addDomainKey(const string& name, const KeyData& key)
{
  if(!d_dnssecQueries)
    return -1;
  char output[16384];  
  snprintf(output,sizeof(output)-1,d_AddDomainKeyQuery.c_str(),
	   key.flags, (int)key.active, sqlEscape(key.content).c_str(), sqlEscape(toLower(name)).c_str());

  try {
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to store key: "+e.txtReason());
  }
  return 1; // XXX FIXME, no idea how to get the id
}

bool GSQLBackend::activateDomainKey(const string& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];
  snprintf(output,sizeof(output)-1,d_ActivateDomainKeyQuery.c_str(), sqlEscape(toLower(name)).c_str(), id);

  try {
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to activate key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::deactivateDomainKey(const string& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];
  snprintf(output,sizeof(output)-1,d_DeactivateDomainKeyQuery.c_str(), sqlEscape(toLower(name)).c_str(), id);

  try {
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to deactivate key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::removeDomainKey(const string& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];
  snprintf(output,sizeof(output)-1,d_RemoveDomainKeyQuery.c_str(), sqlEscape(toLower(name)).c_str(), id);

  try {
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to remove key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getTSIGKey(const string& name, string* algorithm, string* content)
{
  if(!d_dnssecQueries)
    return false;
    
  char output[1024];  
  snprintf(output,sizeof(output)-1,d_getTSIGKeyQuery.c_str(), sqlEscape(toLower(name)).c_str());

  try {
    d_db->doQuery(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to retrieve named TSIG key: "+e.txtReason());
  }
  
  SSql::row_t row;
  
  content->clear();
  while(d_db->getRow(row)) {
    *algorithm = row[0];
    *content=row[1];
  }

  return !content->empty();
}

bool GSQLBackend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];  
  snprintf(output,sizeof(output)-1,d_ListDomainKeysQuery.c_str(), sqlEscape(toLower(name)).c_str());

  try {
    d_db->doQuery(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to list keys: "+e.txtReason());
  }
  
  SSql::row_t row;
  //  "select id, kind, active, content from domains, cryptokeys where domain_id=domains.id and name='%s'";
  KeyData kd;
  while(d_db->getRow(row)) {
    //~ BOOST_FOREACH(const std::string& val, row) {
      //~ cerr<<"'"<<val<<"'"<<endl;
    //~ }
    kd.id = atoi(row[0].c_str());
    kd.flags = atoi(row[1].c_str());
    kd.active = atoi(row[2].c_str());
    kd.content = row[3];
    keys.push_back(kd);
  }

  return true;
}

void GSQLBackend::alsoNotifies(const string &domain, set<string> *ips)
{
  if(!d_dnssecQueries)
    return;
  vector<string> meta;
  getDomainMetadata(domain, "ALSO-NOTIFY", meta);
  BOOST_FOREACH(string& str, meta) {
    ips->insert(str);
  }
}

bool GSQLBackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];  
  snprintf(output,sizeof(output)-1,d_GetDomainMetadataQuery.c_str(), sqlEscape(name).c_str(), sqlEscape(kind).c_str());

  try {
    d_db->doQuery(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to list metadata: "+e.txtReason());
  }
  
  SSql::row_t row;
  
  while(d_db->getRow(row)) {
    meta.push_back(row[0]);
  }
  return true;
}

bool GSQLBackend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{
  char output[16384];  
  if(!d_dnssecQueries)
    return false;

  if(!meta.empty())
    snprintf(output,sizeof(output)-1,d_SetDomainMetadataQuery.c_str(),
      sqlEscape(kind).c_str(), sqlEscape(*meta.begin()).c_str(), sqlEscape(name).c_str());

  string clearQuery = (boost::format(d_ClearDomainMetadataQuery) % sqlEscape(name) % sqlEscape(kind)).str();

  try {
    d_db->doCommand(clearQuery);
    if(!meta.empty())
      d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw AhuException("GSQLBackend unable to store metadata key: "+e.txtReason());
  }
  
  return true;
}


void GSQLBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int domain_id)
{
  string format;
  char output[1024];

  d_db->setLog(::arg().mustDo("query-logging"));

  string lcqname=toLower(qname);
  
  // lcqname=labelReverse(makeRelative(lcqname, "net"));

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

void GSQLBackend::getAllDomains(vector<DomainInfo> *domains) 
{
  DLOG(L<<"GSQLBackend retrieving all domains."<<endl);

  try {
    d_db->doCommand(d_getAllDomainsQuery.c_str()); 
  }
  catch (SSqlException &e) {
    throw AhuException("Database error trying to retrieve all domains:" + e.txtReason());
  }

  SSql::row_t row;
  while (d_db->getRow(row)) {

    DomainInfo di;
    di.id = atol(row[0].c_str());
    di.zone = row[1];

    if (!row[4].empty()) {
      stringtok(di.masters, row[4], " ,\t");
    }
    di.last_check=atol(row[6].c_str());

    SOAData sd;
    fillSOAData(row[2], sd);
    di.serial = sd.serial;
    if (!row[5].empty()) {
      di.notified_serial = atol(row[5].c_str());
    }
    
    if (pdns_iequals(row[3], "MASTER"))
      di.kind = DomainInfo::Master;
    else if (pdns_iequals(row[3], "SLAVE"))
      di.kind = DomainInfo::Slave;
    else
      di.kind = DomainInfo::Native;

    di.backend = this;

    domains->push_back(di);
  }
}

bool GSQLBackend::get(DNSResourceRecord &r)
{
  // L << "GSQLBackend get() was called for "<<qtype.getName() << " record: ";
  SSql::row_t row;
  if(d_db->getRow(row)) {
    r.content=row[0];
    if (row[1].empty())
        r.ttl = ::arg().asNum( "default-ttl" );
    else 
        r.ttl=atol(row[1].c_str());
    r.priority=atol(row[2].c_str());
    if(!d_qname.empty())
      r.qname=d_qname;
    else
      r.qname=row[5];
    r.qtype=row[3];
    r.last_modified=0;
    
    if(d_dnssecQueries)
      r.auth = !row[6].empty() && row[6][0]=='1';
    else
      r.auth = 1; 
    
    r.domain_id=atoi(row[4].c_str());
    return true;
  }
  
  return false;
}

bool GSQLBackend::feedRecord(const DNSResourceRecord &r)
{
  char output[10240];
  if(d_dnssecQueries) {
    snprintf(output,sizeof(output)-1,d_InsertRecordQuery.c_str(),
	   sqlEscape(r.content).c_str(),
	   r.ttl, r.priority,
	   sqlEscape(r.qtype.getName()).c_str(),
	   r.domain_id, toLower(sqlEscape(r.qname)).c_str(), (int)r.auth); 
  }
  else {
    snprintf(output,sizeof(output)-1,d_InsertRecordQuery.c_str(),
	   sqlEscape(r.content).c_str(),
	   r.ttl, r.priority,
	   sqlEscape(r.qtype.getName()).c_str(),
	   r.domain_id, toLower(sqlEscape(r.qname)).c_str()); 
  }
     
     
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
  if(domain_id >= 0) 
   snprintf(output,sizeof(output)-1,d_DeleteZoneQuery.c_str(),domain_id);
  try {
    d_db->doCommand("begin");
    if(domain_id >= 0)
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

bool GSQLBackend::calculateSOASerial(const string& domain, const SOAData& sd, time_t& serial)
{
  if (d_ZoneLastChangeQuery.empty()) {
    // query not set => fall back to default impl
    return DNSBackend::calculateSOASerial(domain, sd, serial);
  }
  
  char output[1024];
  
  snprintf(output, sizeof(output)-1,
           d_ZoneLastChangeQuery.c_str(),
           sd.domain_id);

  try {
    d_db->doQuery(output, d_result);
  }
  catch (const SSqlException& e) {
    //DLOG(L<<"GSQLBackend unable to calculate SOA serial: " << e.txtReason()<<endl);
    return false;
  }

  if (not d_result.empty()) {
    serial = atol(d_result[0][0].c_str());
    return true;
  }

  return false;
}
