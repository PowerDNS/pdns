/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "gsqlbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ueberbackend.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/base32.hh"
#include "pdns/dnssecinfra.hh"
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <boost/foreach.hpp>
#include <boost/format.hpp>


boost::format GSQLformat(const string &query) {
  boost::format format(query);
  format.exceptions(boost::io::no_error_bits);
  return format;
}

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
    throw PDNSException("GSQLBackend unable to refresh domain_id "+itoa(domain_id)+": "+e.txtReason());
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
    throw PDNSException("GSQLBackend unable to refresh domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
}

bool GSQLBackend::isMaster(const string &domain, const string &ip)
{
  string query = (GSQLformat(d_MasterOfDomainsZoneQuery) % sqlEscape(domain)).str();

  try {
    d_db->doQuery(query, d_result);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve list of master domains: "+e.txtReason());
  }

  if(!d_result.empty()) {

    // we can have multiple masters separated by commas
    vector<string> masters;
    stringtok(masters, d_result[0][0], " ,\t");

    BOOST_FOREACH(const string master, masters) {
      const ComboAddress caMaster(master);
      if(ip == caMaster.toString())
        return true;
    }
  }

  // no matching master
  return false;
}

bool GSQLBackend::setMaster(const string &domain, const string &ip)
{
  string query = (GSQLformat(d_UpdateMasterOfZoneQuery) % sqlEscape(ip) % sqlEscape(toLower(domain))).str();

  try {
    d_db->doCommand(query);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set master of domain \""+domain+"\": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::setKind(const string &domain, const DomainInfo::DomainKind kind)
{
  string kind_str = toUpper(DomainInfo::getKindString(kind));
  string query = (GSQLformat(d_UpdateKindOfZoneQuery) % sqlEscape(kind_str) % sqlEscape(toLower(domain))).str();

  try {
    d_db->doCommand(query);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set kind of domain \""+domain+"\": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::setAccount(const string &domain, const string &account)
{
  string query = (GSQLformat(d_UpdateAccountOfZoneQuery) % sqlEscape(account) % sqlEscape(toLower(domain))).str();

  try {
    d_db->doCommand(query);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set account of domain \""+domain+"\": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getDomainInfo(const string &domain, DomainInfo &di)
{
  /* fill DomainInfo from database info:
     id,name,master IP(s),last_check,notified_serial,type,account */
  char output[1024];
  snprintf(output,sizeof(output)-1,d_InfoOfDomainsZoneQuery.c_str(),
	   sqlEscape(domain).c_str());
  try {
    d_db->doQuery(output,d_result);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve information about a domain: "+e.txtReason());
  }

  int numanswers=d_result.size();
  if(!numanswers)
    return false;
  
  di.id=atol(d_result[0][0].c_str());
  di.zone=d_result[0][1];
  stringtok(di.masters, d_result[0][2], " ,\t");
  di.last_check=atol(d_result[0][3].c_str());
  di.notified_serial = atol(d_result[0][4].c_str());
  string type=d_result[0][5];
  di.account=d_result[0][6];
  di.backend=this;

  di.serial = 0;
  try {
    SOAData sd;
    if(!getSOA(domain,sd))
      L<<Logger::Notice<<"No serial for '"<<domain<<"' found - zone is missing?"<<endl;
    else
      di.serial = sd.serial;
  }
  catch(PDNSException &ae){
    L<<Logger::Error<<"Error retrieving serial for '"<<domain<<"': "<<ae.reason<<endl;
  }

  di.kind = DomainInfo::stringToKind(type);

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
    throw PDNSException("GSQLBackend unable to retrieve list of slave domains: "+e.txtReason());
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
    throw PDNSException("GSQLBackend unable to retrieve list of master domains: "+e.txtReason());
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

  d_NoIdQuery=getArg("basic-query");
  d_IdQuery=getArg("id-query");
  d_ANYNoIdQuery=getArg("any-query");
  d_ANYIdQuery=getArg("any-id-query");

  d_listQuery=getArg("list-query");
  d_listSubZoneQuery=getArg("list-subzone-query");

  d_MasterOfDomainsZoneQuery=getArg("master-zone-query");
  d_InfoOfDomainsZoneQuery=getArg("info-zone-query");
  d_InfoOfAllSlaveDomainsQuery=getArg("info-all-slaves-query");
  d_SuperMasterInfoQuery=getArg("supermaster-query");
  d_GetSuperMasterIPs=getArg("supermaster-name-to-ips");
  d_InsertZoneQuery=getArg("insert-zone-query");
  d_InsertSlaveZoneQuery=getArg("insert-slave-query");
  d_InsertRecordQuery=getArg("insert-record-query");
  d_InsertEntQuery=getArg("insert-ent-query");
  d_UpdateMasterOfZoneQuery=getArg("update-master-query");
  d_UpdateKindOfZoneQuery=getArg("update-kind-query");
  d_UpdateAccountOfZoneQuery=getArg("update-account-query");
  d_UpdateSerialOfZoneQuery=getArg("update-serial-query");
  d_UpdateLastCheckofZoneQuery=getArg("update-lastcheck-query");
  d_ZoneLastChangeQuery=getArg("zone-lastchange-query");
  d_InfoOfAllMasterDomainsQuery=getArg("info-all-master-query");
  d_DeleteDomainQuery=getArg("delete-domain-query");
  d_DeleteZoneQuery=getArg("delete-zone-query");
  d_DeleteRRSetQuery=getArg("delete-rrset-query");
  d_DeleteNamesQuery=getArg("delete-names-query");
  d_getAllDomainsQuery=getArg("get-all-domains-query");

  d_removeEmptyNonTerminalsFromZoneQuery = getArg("remove-empty-non-terminals-from-zone-query");
  d_insertEmptyNonTerminalQuery = getArg("insert-empty-non-terminal-query");
  d_deleteEmptyNonTerminalQuery = getArg("delete-empty-non-terminal-query");

  d_ListCommentsQuery = getArg("list-comments-query");
  d_InsertCommentQuery = getArg("insert-comment-query");
  d_DeleteCommentRRsetQuery = getArg("delete-comment-rrset-query");
  d_DeleteCommentsQuery = getArg("delete-comments-query");

  d_InsertRecordOrderQuery=getArg("insert-record-order-query");
  d_InsertEntOrderQuery=getArg("insert-ent-order-query");

  d_firstOrderQuery = getArg("get-order-first-query");
  d_beforeOrderQuery = getArg("get-order-before-query");
  d_afterOrderQuery = getArg("get-order-after-query");
  d_lastOrderQuery = getArg("get-order-last-query");
  d_setOrderAuthQuery = getArg("set-order-and-auth-query");
  d_nullifyOrderNameAndUpdateAuthQuery = getArg("nullify-ordername-and-update-auth-query");
  d_nullifyOrderNameAndAuthQuery = getArg("nullify-ordername-and-auth-query");
  d_setAuthOnDsRecordQuery = getArg("set-auth-on-ds-record-query");

  d_AddDomainKeyQuery = getArg("add-domain-key-query");
  d_ListDomainKeysQuery = getArg("list-domain-keys-query");

  d_GetAllDomainMetadataQuery = getArg("get-all-domain-metadata-query");  
  d_GetDomainMetadataQuery = getArg("get-domain-metadata-query");
  d_ClearDomainMetadataQuery = getArg("clear-domain-metadata-query");
  d_ClearDomainAllMetadataQuery = getArg("clear-domain-all-metadata-query");
  d_SetDomainMetadataQuery = getArg("set-domain-metadata-query");

  d_ActivateDomainKeyQuery = getArg("activate-domain-key-query");
  d_DeactivateDomainKeyQuery = getArg("deactivate-domain-key-query");
  d_RemoveDomainKeyQuery = getArg("remove-domain-key-query");
  d_ClearDomainAllKeysQuery = getArg("clear-domain-all-keys-query");

  d_getTSIGKeyQuery = getArg("get-tsig-key-query");
  d_setTSIGKeyQuery = getArg("set-tsig-key-query");
  d_deleteTSIGKeyQuery = getArg("delete-tsig-key-query");
  d_getTSIGKeysQuery = getArg("get-tsig-keys-query");
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

  snprintf(output, sizeof(output)-1, d_setOrderAuthQuery.c_str(), sqlEscape(ordername).c_str(), auth, sqlEscape(toLower(qname)).c_str(), domain_id);
  try {
    d_db->doCommand(output);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to update ordername/auth for domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::nullifyDNSSECOrderNameAndUpdateAuth(uint32_t domain_id, const std::string& qname, bool auth)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];

  snprintf(output, sizeof(output)-1, d_nullifyOrderNameAndUpdateAuthQuery.c_str(), auth, domain_id, sqlEscape(toLower(qname)).c_str());
  try {
    d_db->doCommand(output);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to nullify ordername and update auth for domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::nullifyDNSSECOrderNameAndAuth(uint32_t domain_id, const std::string& qname, const std::string& type)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];

  snprintf(output, sizeof(output)-1, d_nullifyOrderNameAndAuthQuery.c_str(), sqlEscape(toLower(qname)).c_str(), sqlEscape(type).c_str(), domain_id);
  try {
    d_db->doCommand(output);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to nullify ordername/auth for domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::setDNSSECAuthOnDsRecord(uint32_t domain_id, const std::string& qname)
{
  if(!d_dnssecQueries)
    return false;
  char output[1024];

  snprintf(output, sizeof(output)-1, d_setAuthOnDsRecordQuery.c_str(), domain_id, sqlEscape(qname).c_str());
  try {
    d_db->doCommand(output);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set auth on DS record "+qname+" for domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::updateEmptyNonTerminals(uint32_t domain_id, const std::string& zonename, set<string>& insert, set<string>& erase, bool remove)
{
  char output[1024];

  if(remove) {
    snprintf(output,sizeof(output)-1,d_removeEmptyNonTerminalsFromZoneQuery.c_str(), domain_id);
    try {
      d_db->doCommand(output);
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to delete empty non-terminal records from domain_id "+itoa(domain_id)+": "+e.txtReason());
      return false;
    }
  }
  else
  {
    BOOST_FOREACH(const string qname, erase) {
      snprintf(output,sizeof(output)-1,d_deleteEmptyNonTerminalQuery.c_str(), domain_id, sqlEscape(qname).c_str());
      try {
        d_db->doCommand(output);
      }
      catch (SSqlException &e) {
        throw PDNSException("GSQLBackend unable to delete empty non-terminal rr "+qname+" from domain_id "+itoa(domain_id)+": "+e.txtReason());
        return false;
      }
    }
  }

  BOOST_FOREACH(const string qname, insert) {
    snprintf(output,sizeof(output)-1,d_insertEmptyNonTerminalQuery.c_str(), domain_id, sqlEscape(qname).c_str());
    try {
      d_db->doCommand(output);
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to insert empty non-terminal rr "+qname+" in domain_id "+itoa(domain_id)+": "+e.txtReason());
      return false;
    }
  }

  return true;
}

bool GSQLBackend::doesDNSSEC()
{
    return d_dnssecQueries;
}

bool GSQLBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)
{
  if(!d_dnssecQueries)
    return false;
  // cerr<<"gsql before/after called for id="<<id<<", qname='"<<qname<<"'"<<endl;
  after.clear();
  string lcqname=toLower(qname);

  SSql::row_t row;

  char output[1024];

  snprintf(output, sizeof(output)-1, d_afterOrderQuery.c_str(), sqlEscape(lcqname).c_str(), id);
  try {
    d_db->doQuery(output);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to find before/after (after) for domain_id "+itoa(id)+": "+e.txtReason());
  }
  while(d_db->getRow(row)) {
    after=row[0];
  }

  if(after.empty() && !lcqname.empty()) {
    snprintf(output, sizeof(output)-1, d_firstOrderQuery.c_str(), id);
    try {
      d_db->doQuery(output);
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (first) for domain_id "+itoa(id)+": "+e.txtReason());
    }
    while(d_db->getRow(row)) {
      after=row[0];
    }
  }

  if (before.empty()) {
    unhashed.clear();

    snprintf(output, sizeof(output)-1, d_beforeOrderQuery.c_str(), sqlEscape(lcqname).c_str(), id);
    try {
      d_db->doQuery(output);
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (before) for domain_id "+itoa(id)+": "+e.txtReason());
    }
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
    try {
      d_db->doQuery(output);
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (last) for domain_id "+itoa(id)+": "+e.txtReason());
    }
    while(d_db->getRow(row)) {
      before=row[0];
      unhashed=row[1];
    }
  } else {
    before=lcqname;
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
    throw PDNSException("GSQLBackend unable to store key: "+e.txtReason());
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
    throw PDNSException("GSQLBackend unable to activate key: "+e.txtReason());
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
    throw PDNSException("GSQLBackend unable to deactivate key: "+e.txtReason());
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
    throw PDNSException("GSQLBackend unable to remove key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getTSIGKey(const string& name, string* algorithm, string* content)
{
  char output[1024];  
  snprintf(output,sizeof(output)-1,d_getTSIGKeyQuery.c_str(), sqlEscape(toLower(name)).c_str());

  try {
    d_db->doQuery(output);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve named TSIG key: "+e.txtReason());
  }
  
  SSql::row_t row;

  content->clear();
  while(d_db->getRow(row)) {
    if(row.size() >= 2 && (algorithm->empty() || pdns_iequals(*algorithm, row[0]))) {
      *algorithm = row[0];
      *content = row[1];
    }
  }

  return !content->empty();
}

bool GSQLBackend::setTSIGKey(const string& name, const string& algorithm, const string& content)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,d_setTSIGKeyQuery.c_str(), sqlEscape(toLower(name)).c_str(), sqlEscape(toLower(algorithm)).c_str(), sqlEscape(content).c_str());
  try {
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to store named TSIG key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::deleteTSIGKey(const string& name)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,d_deleteTSIGKeyQuery.c_str(), sqlEscape(toLower(name)).c_str());
  try {
    d_db->doCommand(output);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to store named TSIG key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,"%s",d_getTSIGKeysQuery.c_str());

  try {
    d_db->doQuery(output);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve TSIG keys: "+e.txtReason());
  }

  SSql::row_t row;

  while(d_db->getRow(row)) {
     struct TSIGKey key;
     key.name = row[0];
     key.algorithm = row[1];
     key.key = row[2];
     keys.push_back(key);
  }

  return keys.empty();
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
    throw PDNSException("GSQLBackend unable to list keys: "+e.txtReason());
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
  vector<string> meta;
  getDomainMetadata(domain, "ALSO-NOTIFY", meta);
  BOOST_FOREACH(string& str, meta) {
    ips->insert(str);
  }
}

bool GSQLBackend::getAllDomainMetadata(const string& name, std::map<std::string, std::vector<std::string> >& meta)
{
  char output[1024];
  snprintf(output,sizeof(output)-1,d_GetAllDomainMetadataQuery.c_str(), sqlEscape(name).c_str());

  try {
    d_db->doQuery(output);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list metadata: "+e.txtReason());
  }

  SSql::row_t row;

  while(d_db->getRow(row)) {
    if (!isDnssecDomainMetadata(row[0]))
      meta[row[0]].push_back(row[1]);
  }

  return true;
}


bool GSQLBackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{
  if(!d_dnssecQueries && isDnssecDomainMetadata(kind))
    return false;

  char output[1024];
  snprintf(output,sizeof(output)-1,d_GetDomainMetadataQuery.c_str(), sqlEscape(toLower(name)).c_str(), sqlEscape(kind).c_str());

  try {
    d_db->doQuery(output);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list metadata: "+e.txtReason());
  }
  
  SSql::row_t row;
  
  while(d_db->getRow(row)) {
    meta.push_back(row[0]);
  }
  return true;
}

bool GSQLBackend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{
  if(!d_dnssecQueries && isDnssecDomainMetadata(kind))
    return false;

  char output[16384];  
  string clearQuery = (GSQLformat(d_ClearDomainMetadataQuery) % sqlEscape(toLower(name)) % sqlEscape(kind)).str();

  try {
    d_db->doCommand(clearQuery);
    if(!meta.empty()) {
      BOOST_FOREACH(const std::string & value, meta) {
         snprintf(output,sizeof(output)-1,d_SetDomainMetadataQuery.c_str(),
            sqlEscape(kind).c_str(), sqlEscape(value).c_str(), sqlEscape(toLower(name)).c_str());
         d_db->doCommand(output);
      }
    }
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to store metadata key: "+e.txtReason());
  }
  
  return true;
}

void GSQLBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int domain_id)
{
  string lcqname=toLower(qname);

  string query;
  if(qtype.getCode()!=QType::ANY) {
    if(domain_id < 0) {
      query = (GSQLformat(d_NoIdQuery)
               % sqlEscape(qtype.getName())
               % sqlEscape(lcqname)
        ).str();
    } else {
      query = (GSQLformat(d_IdQuery)
               % sqlEscape(qtype.getName())
               % sqlEscape(lcqname)
               % domain_id
        ).str();
    }
  } else {
    // qtype==ANY
    if(domain_id < 0) {
      query = (GSQLformat(d_ANYNoIdQuery)
               % sqlEscape(lcqname)
        ).str();
    } else {
      query = (GSQLformat(d_ANYIdQuery)
               % sqlEscape(lcqname)
               % domain_id
        ).str();
    }
  }

  try {
    d_db->doQuery(query);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend lookup query:"+e.txtReason());
  }

  d_qname=qname;
}

bool GSQLBackend::list(const string &target, int domain_id, bool include_disabled)
{
  DLOG(L<<"GSQLBackend constructing handle for list of domain id '"<<domain_id<<"'"<<endl);

  string query = (GSQLformat(d_listQuery)
                  % (int)include_disabled
                  % domain_id
    ).str();

  try {
    d_db->doQuery(query);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend list query: "+e.txtReason());
  }

  d_qname="";
  return true;
}

bool GSQLBackend::listSubZone(const string &zone, int domain_id) {
  string wildzone = "%." + zone;
  string query = (GSQLformat(d_listSubZoneQuery)
                  % sqlEscape(zone)
                  % sqlEscape(wildzone)
                  % domain_id
    ).str();
  try {
    d_db->doQuery(query);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend listSubZone query: "+e.txtReason());
  }
  d_qname="";
  return true;
}



bool GSQLBackend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **ddb)
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
      throw PDNSException("GSQLBackend unable to search for a domain: "+e.txtReason());
    }

    if(!d_result.empty()) {
      *nameserver=i->content;
      *account=d_result[0][0];
      *ddb=this;
      return true;
    }
  }
  return false;
}

bool GSQLBackend::createDomain(const string &domain)
{
  string query = (GSQLformat(d_InsertZoneQuery) % toLower(sqlEscape(domain))).str();
  try {
    d_db->doCommand(query);
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to insert new domain '"+domain+"': "+ e.txtReason());
  }
  return true;
}

bool GSQLBackend::createSlaveDomain(const string &ip, const string &domain, const string &nameserver, const string &account)
{
  string format;
  string name;
  string masters(ip);

  char output[1024];
  try {
    if (!nameserver.empty()) {
      // figure out all IP addresses for the master
      format = d_GetSuperMasterIPs;
      snprintf(output,sizeof(output)-1,format.c_str(),sqlEscape(nameserver).c_str(),sqlEscape(account).c_str());
      d_db->doQuery(output, d_result);
      if (!d_result.empty()) {
        // collect all IP addresses
        vector<string> tmp;
        BOOST_FOREACH(SSql::row_t& row, d_result) {
          if (account == row[1])
            tmp.push_back(row[0]);
        }
        // set them as domain's masters, comma separated
        masters = boost::join(tmp, ", ");
      }
    }
    format = d_InsertSlaveZoneQuery;
    snprintf(output,sizeof(output)-1,format.c_str(),sqlEscape(domain).c_str(),sqlEscape(masters).c_str(),sqlEscape(account).c_str());
    d_db->doCommand(output);
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to insert new slave domain '"+domain+"': "+ e.txtReason());
  }
  return true;
}

bool GSQLBackend::deleteDomain(const string &domain)
{
  string sqlDomain = sqlEscape(toLower(domain));

  DomainInfo di;
  if (!getDomainInfo(domain, di)) {
    return false;
  }

  string recordsQuery = (GSQLformat(d_DeleteZoneQuery) % di.id).str();
  string metadataQuery;
  string keysQuery;
  string commentsQuery = (GSQLformat(d_DeleteCommentsQuery) % di.id).str();
  string domainQuery = (GSQLformat(d_DeleteDomainQuery) % sqlDomain).str();

  metadataQuery = (GSQLformat(d_ClearDomainAllMetadataQuery) % sqlDomain).str();
  keysQuery = (GSQLformat(d_ClearDomainAllKeysQuery) % sqlDomain).str();

  try {
    d_db->doCommand(recordsQuery);
    d_db->doCommand(metadataQuery);
    d_db->doCommand(keysQuery);
    d_db->doCommand(commentsQuery);
    d_db->doCommand(domainQuery);
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to delete domain '"+domain+"': "+ e.txtReason());
  }
  return true;
}

void GSQLBackend::getAllDomains(vector<DomainInfo> *domains, bool include_disabled)
{
  DLOG(L<<"GSQLBackend retrieving all domains."<<endl);
  string query = (GSQLformat(d_getAllDomainsQuery) % (int)include_disabled).str();

  try {
    d_db->doQuery(query);
  }
  catch (SSqlException &e) {
    throw PDNSException("Database error trying to retrieve all domains:" + e.txtReason());
  }

  SSql::row_t row;
  while (d_db->getRow(row)) {

    DomainInfo di;
    di.id = atol(row[0].c_str());
    di.zone = row[1];

    if (!row[4].empty()) {
      stringtok(di.masters, row[4], " ,\t");
    }

    SOAData sd;
    fillSOAData(row[2], sd);
    di.serial = sd.serial;
    di.notified_serial = atol(row[5].c_str());
    di.last_check = atol(row[6].c_str());
    di.account = row[7];
    
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
      r.qname=row[6];
    r.qtype=row[3];
    r.last_modified=0;
    
    if(d_dnssecQueries)
      r.auth = !row[7].empty() && row[7][0]=='1';
    else
      r.auth = 1; 

    r.disabled = !row[5].empty() && row[5][0]=='1';

    r.domain_id=atoi(row[4].c_str());
    return true;
  }
  
  return false;
}

bool GSQLBackend::replaceRRSet(uint32_t domain_id, const string& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  string query;
  if (qt != QType::ANY) {
    query = (GSQLformat(d_DeleteRRSetQuery)
             % domain_id
             % sqlEscape(qname)
             % sqlEscape(qt.getName())
      ).str();
  } else {
    query = (GSQLformat(d_DeleteNamesQuery)
             % domain_id
             % sqlEscape(qname)
      ).str();
  }
  try {
    d_db->doCommand(query);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to delete RRSet: "+e.txtReason());
  }

  if (rrset.empty()) {
    // zap comments for now non-existing rrset
    query = (GSQLformat(d_DeleteCommentRRsetQuery)
             % domain_id
             % sqlEscape(qname)
             % sqlEscape(qt.getName())
      ).str();
    try {
      d_db->doCommand(query);
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to delete comment: "+e.txtReason());
    }
  }
  BOOST_FOREACH(const DNSResourceRecord& rr, rrset) {
    feedRecord(rr);
  }
  
  return true;
}

bool GSQLBackend::feedRecord(const DNSResourceRecord &r, string *ordername)
{
  string query;

  if(d_dnssecQueries && ordername)
    query = (GSQLformat(d_InsertRecordOrderQuery)
             % sqlEscape(r.content)
             % r.ttl
             % r.priority
             % sqlEscape(r.qtype.getName())
             % r.domain_id
             % (int)r.disabled
             % toLower(sqlEscape(r.qname))
             % sqlEscape(*ordername)
             % (int)(r.auth)
      ).str();
  else
    query = (GSQLformat(d_InsertRecordQuery)
             % sqlEscape(r.content)
             % r.ttl
             % r.priority
             % sqlEscape(r.qtype.getName())
             % r.domain_id
             % (int)r.disabled
             % toLower(sqlEscape(r.qname))
             % (int)(r.auth || !d_dnssecQueries)
      ).str();

  try {
    d_db->doCommand(query);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to feed record: "+e.txtReason());
  }
  return true; // XXX FIXME this API should not return 'true' I think -ahu 
}

bool GSQLBackend::feedEnts(int domain_id, map<string,bool>& nonterm)
{
  string query;
  pair<string,bool> nt;

  BOOST_FOREACH(nt, nonterm) {

    query = (GSQLformat(d_InsertEntQuery)
             % domain_id
             % toLower(sqlEscape(nt.first))
             % (int)(nt.second || !d_dnssecQueries)
      ).str();

    try {
      d_db->doCommand(query);
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to feed empty non-terminal: "+e.txtReason());
    }
  }
  return true;
}

bool GSQLBackend::feedEnts3(int domain_id, const string &domain, map<string,bool> &nonterm, unsigned int times, const string &salt, bool narrow)
{
  if(!d_dnssecQueries)
      return false;

  string ordername, query;
  pair<string,bool> nt;

  BOOST_FOREACH(nt, nonterm) {

    if(narrow || !nt.second) {
      query = (GSQLformat(d_InsertEntQuery)
               % domain_id
               % toLower(sqlEscape(nt.first))
               % nt.second
       ).str();
    } else {
      ordername=toBase32Hex(hashQNameWithSalt(times, salt, nt.first));
      query = (GSQLformat(d_InsertEntOrderQuery)
               % domain_id
               % toLower(sqlEscape(nt.first))
               % toLower(sqlEscape(ordername))
               % nt.second
       ).str();
    }

    try {
      d_db->doCommand(query);
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to feed empty non-terminal: "+e.txtReason());
    }
  }
  return true;
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
    throw PDNSException("Database failed to start transaction: "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::commitTransaction()
{
  try {
    d_db->doCommand("commit");
  }
  catch (SSqlException &e) {
    throw PDNSException("Database failed to commit transaction: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::abortTransaction()
{
  try {
    d_db->doCommand("rollback");
  }
  catch(SSqlException &e) {
    throw PDNSException("Database failed to abort transaction: "+string(e.txtReason()));
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

bool GSQLBackend::listComments(const uint32_t domain_id)
{
  string query = (GSQLformat(d_ListCommentsQuery)
                  % domain_id
    ).str();

  try {
    d_db->doQuery(query);
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend list comments query: "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::getComment(Comment& comment)
{
  SSql::row_t row;

  if (!d_db->getRow(row)) {
    return false;
  }

  // domain_id,name,type,modified_at,account,comment
  comment.domain_id = atol(row[0].c_str());
  comment.qname = row[1];
  comment.qtype = row[2];
  comment.modified_at = atol(row[3].c_str());
  comment.account = row[4];
  comment.content = row[5];

  return true;
}

void GSQLBackend::feedComment(const Comment& comment)
{
  string query = (GSQLformat(d_InsertCommentQuery)
                  % comment.domain_id
                  % toLower(sqlEscape(comment.qname))
                  % sqlEscape(comment.qtype.getName())
                  % comment.modified_at
                  % sqlEscape(comment.account)
                  % sqlEscape(comment.content)
    ).str();

  try {
    d_db->doCommand(query);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to feed comment: "+e.txtReason());
  }
}

bool GSQLBackend::replaceComments(const uint32_t domain_id, const string& qname, const QType& qt, const vector<Comment>& comments)
{
  string query;
    query = (GSQLformat(d_DeleteCommentRRsetQuery)
             % domain_id
             % toLower(sqlEscape(qname))
             % sqlEscape(qt.getName())
      ).str();

  try {
    d_db->doCommand(query);
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to delete comment: "+e.txtReason());
  }

  BOOST_FOREACH(const Comment& comment, comments) {
    feedComment(comment);
  }

  return true;
}
