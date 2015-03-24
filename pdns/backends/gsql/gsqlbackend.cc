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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
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
#include <boost/scoped_ptr.hpp>

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
  d_UpdateSerialOfZoneQuery=getArg("update-serial-query");
  d_UpdateLastCheckofZoneQuery=getArg("update-lastcheck-query");
  d_UpdateAccountOfZoneQuery=getArg("update-account-query");
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

  d_query_stmt = NULL;
  d_NoIdQuery_stmt = NULL;
  d_IdQuery_stmt = NULL;
  d_ANYNoIdQuery_stmt = NULL;
  d_ANYIdQuery_stmt = NULL;
  d_listQuery_stmt = NULL;
  d_listSubZoneQuery_stmt = NULL;
  d_MasterOfDomainsZoneQuery_stmt = NULL;
  d_InfoOfDomainsZoneQuery_stmt = NULL;
  d_InfoOfAllSlaveDomainsQuery_stmt = NULL;
  d_SuperMasterInfoQuery_stmt = NULL;
  d_GetSuperMasterIPs_stmt = NULL;
  d_InsertZoneQuery_stmt = NULL;
  d_InsertSlaveZoneQuery_stmt = NULL;
  d_InsertRecordQuery_stmt = NULL;
  d_InsertEntQuery_stmt = NULL;
  d_InsertRecordOrderQuery_stmt = NULL;
  d_InsertEntOrderQuery_stmt = NULL;
  d_UpdateMasterOfZoneQuery_stmt = NULL;
  d_UpdateKindOfZoneQuery_stmt = NULL;
  d_UpdateSerialOfZoneQuery_stmt = NULL;
  d_UpdateLastCheckofZoneQuery_stmt = NULL;
  d_UpdateAccountOfZoneQuery_stmt = NULL;
  d_InfoOfAllMasterDomainsQuery_stmt = NULL;
  d_DeleteDomainQuery_stmt = NULL;
  d_DeleteZoneQuery_stmt = NULL;
  d_DeleteRRSetQuery_stmt = NULL;
  d_DeleteNamesQuery_stmt = NULL;
  d_ZoneLastChangeQuery_stmt = NULL;
  d_firstOrderQuery_stmt = NULL;
  d_beforeOrderQuery_stmt = NULL;
  d_afterOrderQuery_stmt = NULL;
  d_lastOrderQuery_stmt = NULL;
  d_setOrderAuthQuery_stmt = NULL;
  d_nullifyOrderNameAndUpdateAuthQuery_stmt = NULL;
  d_nullifyOrderNameAndAuthQuery_stmt = NULL;
  d_nullifyOrderNameAndAuthENTQuery_stmt = NULL;
  d_setAuthOnDsRecordQuery_stmt = NULL;
  d_removeEmptyNonTerminalsFromZoneQuery_stmt = NULL;
  d_insertEmptyNonTerminalQuery_stmt = NULL;
  d_deleteEmptyNonTerminalQuery_stmt = NULL;
  d_AddDomainKeyQuery_stmt = NULL;
  d_ListDomainKeysQuery_stmt = NULL;
  d_GetAllDomainMetadataQuery_stmt = NULL;
  d_GetDomainMetadataQuery_stmt = NULL;
  d_ClearDomainMetadataQuery_stmt = NULL;
  d_ClearDomainAllMetadataQuery_stmt = NULL;
  d_SetDomainMetadataQuery_stmt = NULL;
  d_RemoveDomainKeyQuery_stmt = NULL;
  d_ActivateDomainKeyQuery_stmt = NULL;
  d_DeactivateDomainKeyQuery_stmt = NULL;
  d_ClearDomainAllKeysQuery_stmt = NULL;
  d_getTSIGKeyQuery_stmt = NULL;
  d_setTSIGKeyQuery_stmt = NULL;
  d_deleteTSIGKeyQuery_stmt = NULL;
  d_getTSIGKeysQuery_stmt = NULL;
  d_getAllDomainsQuery_stmt = NULL;
  d_ListCommentsQuery_stmt = NULL;
  d_InsertCommentQuery_stmt = NULL;
  d_DeleteCommentRRsetQuery_stmt = NULL;
  d_DeleteCommentsQuery_stmt = NULL;
}

void GSQLBackend::setNotified(uint32_t domain_id, uint32_t serial)
{
  try {
    d_UpdateSerialOfZoneQuery_stmt->
      bind("serial", serial)->
      bind("domain_id", domain_id)->
      execute()->
      reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to refresh domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
}

void GSQLBackend::setFresh(uint32_t domain_id)
{
  try {
    d_UpdateLastCheckofZoneQuery_stmt->
      bind("last_check", time(0))->
      bind("domain_id", domain_id)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to refresh domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
}

bool GSQLBackend::isMaster(const string &domain, const string &ip)
{
  try {
    d_MasterOfDomainsZoneQuery_stmt->
      bind("domain", domain)->
      execute()->
      getResult(d_result)->
      reset();
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
  try {
    d_UpdateMasterOfZoneQuery_stmt->
      bind("master", ip)->
      bind("domain", toLower(domain))->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set master of domain \""+domain+"\": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::setKind(const string &domain, const DomainInfo::DomainKind kind)
{
  try {
    d_UpdateKindOfZoneQuery_stmt->
      bind("kind", toUpper(DomainInfo::getKindString(kind)))->
      bind("domain", toLower(domain))->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set kind of domain \""+domain+"\": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::setAccount(const string &domain, const string &account)
{
  try {
    d_UpdateAccountOfZoneQuery_stmt->
            bind("account", account)->
            bind("domain", toLower(domain))->
            execute()->
            reset();
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
  try {
    d_InfoOfDomainsZoneQuery_stmt->
      bind("domain", toLower(domain))->
      execute()->
      getResult(d_result)->
      reset();
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
    d_InfoOfAllSlaveDomainsQuery_stmt->
      execute()->
      getResult(d_result)->
      reset();
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
    d_InfoOfAllMasterDomainsQuery_stmt->
      execute()->
      getResult(d_result)->
      reset();
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

  try {
    d_setOrderAuthQuery_stmt->
      bind("ordername", ordername)->
      bind("auth", auth)->
      bind("qname", qname)->
      bind("domain_id", domain_id)->
      execute()->
      reset();
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

  try {
    d_nullifyOrderNameAndUpdateAuthQuery_stmt->
      bind("auth", auth)->
      bind("domain_id", domain_id)->
      bind("qname", qname)->
      execute()->
      reset();
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
  
  try {
    d_nullifyOrderNameAndAuthQuery_stmt->
      bind("qname", qname)->
      bind("qtype", type)->
      bind("domain_id", domain_id)->
      execute()->
      reset();
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

  try {
    d_setAuthOnDsRecordQuery_stmt->
      bind("domain_id", domain_id)->
      bind("qname", qname)->
      execute()->
      reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set auth on DS record "+qname+" for domain_id "+itoa(domain_id)+": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::updateEmptyNonTerminals(uint32_t domain_id, const std::string& zonename, set<string>& insert, set<string>& erase, bool remove)
{
  if(remove) {
    try {
      d_removeEmptyNonTerminalsFromZoneQuery_stmt->
        bind("domain_id", domain_id)->
        execute()->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to delete empty non-terminal records from domain_id "+itoa(domain_id)+": "+e.txtReason());
      return false;
    }
  }
  else
  {
    BOOST_FOREACH(const string qname, erase) {
      try {
        d_deleteEmptyNonTerminalQuery_stmt->
          bind("domain_id", domain_id)->
          bind("qname", qname)->
          execute()->
          reset();
      }
      catch (SSqlException &e) {
        throw PDNSException("GSQLBackend unable to delete empty non-terminal rr "+qname+" from domain_id "+itoa(domain_id)+": "+e.txtReason());
        return false;
      }
    }
  }

  BOOST_FOREACH(const string qname, insert) {
    try {
      d_insertEmptyNonTerminalQuery_stmt->
        bind("domain_id", domain_id)->
        bind("qname", qname)->
        execute()->
        reset();
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

  SSqlStatement::row_t row;
  try {
    d_afterOrderQuery_stmt->
      bind("ordername", lcqname)->
      bind("domain_id", id)->
      execute();
    while(d_afterOrderQuery_stmt->hasNextRow()) {
      d_afterOrderQuery_stmt->nextRow(row);
      after=row[0];
    }
    d_afterOrderQuery_stmt->reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to find before/after (after) for domain_id "+itoa(id)+": "+e.txtReason());
  }

  if(after.empty() && !lcqname.empty()) {
    try {
      d_firstOrderQuery_stmt->
        bind("domain_id", id)->
        execute();
      while(d_firstOrderQuery_stmt->hasNextRow()) {
        d_firstOrderQuery_stmt->nextRow(row);
        after=row[0];
      }
      d_firstOrderQuery_stmt->reset();
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (first) for domain_id "+itoa(id)+": "+e.txtReason());
    }
  }

  if (before.empty()) {
    unhashed.clear();

    try {
      d_beforeOrderQuery_stmt->
        bind("ordername", lcqname)->
        bind("domain_id", id)->
        execute();
      while(d_beforeOrderQuery_stmt->hasNextRow()) {
        d_beforeOrderQuery_stmt->nextRow(row);
        before=row[0];
        unhashed=row[1];
      }
      d_beforeOrderQuery_stmt->reset();
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (before) for domain_id "+itoa(id)+": "+e.txtReason());
    }

    if(! unhashed.empty())
    {
      // cerr<<"unhashed="<<unhashed<<",before="<<before<<", after="<<after<<endl;
      return true;
    }

    try {
      d_lastOrderQuery_stmt->
        bind("domain_id", id)->
        execute();
      while(d_lastOrderQuery_stmt->hasNextRow()) {
        d_lastOrderQuery_stmt->nextRow(row);
        before=row[0];
        unhashed=row[1];
      }
      d_lastOrderQuery_stmt->reset();
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (last) for domain_id "+itoa(id)+": "+e.txtReason());
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

  try {
    d_AddDomainKeyQuery_stmt->
      bind("flags", key.flags)->
      bind("active", key.active)->
      bind("content", key.content)->
      bind("domain", toLower(name))->
      execute()->
      reset();
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

  try {
    d_ActivateDomainKeyQuery_stmt->
      bind("domain", toLower(name))->
      bind("key_id", id)->
      execute()->
      reset();
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

  try {
    d_DeactivateDomainKeyQuery_stmt->
      bind("domain", toLower(name))->
      bind("key_id", id)->
      execute()->
      reset();
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

  try {
    d_RemoveDomainKeyQuery_stmt->
      bind("domain", toLower(name))->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to remove key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getTSIGKey(const string& name, string* algorithm, string* content)
{
  try {
    d_getTSIGKeyQuery_stmt->
      bind("key_name", toLower(name))->
      execute();
  
    SSqlStatement::row_t row;

    content->clear();
    while(d_getTSIGKeyQuery_stmt->hasNextRow()) {
      d_getTSIGKeyQuery_stmt->nextRow(row);
      if(row.size() >= 2 && (algorithm->empty() || pdns_iequals(*algorithm, row[0]))) {
        *algorithm = row[0];
        *content = row[1];
      }
    }

    d_getTSIGKeyQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve named TSIG key: "+e.txtReason());
  }

  return !content->empty();
}

bool GSQLBackend::setTSIGKey(const string& name, const string& algorithm, const string& content)
{
  try {
    d_setTSIGKeyQuery_stmt->
      bind("key_name", toLower(name))->
      bind("algorithm", toLower(algorithm))->
      bind("content", content)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to store named TSIG key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::deleteTSIGKey(const string& name)
{
  try {
    d_deleteTSIGKeyQuery_stmt->
      bind("key_name", toLower(name))->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to store named TSIG key: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{
  try {
    d_getTSIGKeysQuery_stmt->
      execute();

    SSqlStatement::row_t row;
  
    while(d_getTSIGKeysQuery_stmt->hasNextRow()) {
      d_getTSIGKeysQuery_stmt->nextRow(row);
      struct TSIGKey key;
      key.name = row[0];
      key.algorithm = row[1];
      key.key = row[2];
      keys.push_back(key);
    }

    d_getTSIGKeysQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve TSIG keys: "+e.txtReason());
  }

  return keys.empty();
}

bool GSQLBackend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
{
  if(!d_dnssecQueries)
    return false;

  try {
    d_ListDomainKeysQuery_stmt->
      bind("domain", toLower(name))->
      execute();
  
    SSqlStatement::row_t row;
    //  "select id, kind, active, content from domains, cryptokeys where domain_id=domains.id and name='%s'";
    KeyData kd;
    while(d_ListDomainKeysQuery_stmt->hasNextRow()) {
      d_ListDomainKeysQuery_stmt->nextRow(row);
      //~ BOOST_FOREACH(const std::string& val, row) {
        //~ cerr<<"'"<<val<<"'"<<endl;
      //~ }
      kd.id = atoi(row[0].c_str());
      kd.flags = atoi(row[1].c_str());
      kd.active = atoi(row[2].c_str());
      kd.content = row[3];
      keys.push_back(kd);
    }

    d_ListDomainKeysQuery_stmt->reset();    
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list keys: "+e.txtReason());
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
  try {
    d_GetAllDomainMetadataQuery_stmt->
      bind("domain", toLower(name))->
      execute();

    SSqlStatement::row_t row;
  
    while(d_GetAllDomainMetadataQuery_stmt->hasNextRow()) {
      d_GetAllDomainMetadataQuery_stmt->nextRow(row);
      if (!isDnssecDomainMetadata(row[0]))
        meta[row[0]].push_back(row[1]);
    }

    d_GetAllDomainMetadataQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list metadata: "+e.txtReason());
  }

  return true;
}


bool GSQLBackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{
  if(!d_dnssecQueries && isDnssecDomainMetadata(kind))
    return false;

  try {
    d_GetDomainMetadataQuery_stmt->
      bind("domain", toLower(name))->
      bind("kind", kind)->
      execute();
  
    SSqlStatement::row_t row;
    
    while(d_GetDomainMetadataQuery_stmt->hasNextRow()) {
      d_GetDomainMetadataQuery_stmt->nextRow(row);
      meta.push_back(row[0]);
    }

    d_GetDomainMetadataQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list metadata: "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{
  if(!d_dnssecQueries && isDnssecDomainMetadata(kind))
    return false;

  try {
    d_ClearDomainMetadataQuery_stmt->
      bind("domain", toLower(name))->
      bind("kind", kind)->
      execute()->
      reset();
    if(!meta.empty()) {
      BOOST_FOREACH(const std::string & value, meta) {
         d_SetDomainMetadataQuery_stmt->
           bind("kind", kind)->
           bind("content", value)->
           bind("domain", toLower(name))->
           execute()->
           reset();
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

  try {
    if(qtype.getCode()!=QType::ANY) {
      if(domain_id < 0) {
        d_query_stmt = d_NoIdQuery_stmt;
        d_query_stmt->
          bind("qtype", qtype.getName())->
          bind("qname", lcqname);
      } else {
        d_query_stmt = d_IdQuery_stmt;
        d_query_stmt->
          bind("qtype", qtype.getName())->
          bind("qname", lcqname)->
          bind("domain_id", domain_id);
      }
    } else {
      // qtype==ANY
      if(domain_id < 0) {
        d_query_stmt = d_ANYNoIdQuery_stmt;
        d_query_stmt->
          bind("qname", lcqname);
      } else {
        d_query_stmt = d_ANYIdQuery_stmt;
        d_query_stmt->
          bind("qname", lcqname)->
          bind("domain_id", domain_id);
      }
    }

    d_query_stmt->
      execute();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend lookup query:"+e.txtReason());
  }

  d_qname=qname;
}

bool GSQLBackend::list(const string &target, int domain_id, bool include_disabled)
{
  DLOG(L<<"GSQLBackend constructing handle for list of domain id '"<<domain_id<<"'"<<endl);

  try {
    d_query_stmt = d_listQuery_stmt;
    d_query_stmt->
      bind("include_disabled", (int)include_disabled)->
      bind("domain_id", domain_id)->
      execute();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend list query: "+e.txtReason());
  }

  d_qname="";
  return true;
}

bool GSQLBackend::listSubZone(const string &zone, int domain_id) {
  string wildzone = "%." + zone;

  try {
    d_query_stmt = d_listSubZoneQuery_stmt;
    d_query_stmt->
      bind("zone", zone)->
      bind("wildzone", wildzone)->
      bind("domain_id", domain_id)->
      execute();      
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend listSubZone query: "+e.txtReason());
  }
  d_qname="";
  return true;
}

bool GSQLBackend::get(DNSResourceRecord &r)
{
  // L << "GSQLBackend get() was called for "<<qtype.getName() << " record: ";
  SSqlStatement::row_t row;
  if(d_query_stmt->hasNextRow()) {
    try {
      d_query_stmt->nextRow(row);
    } catch (SSqlException &e) {
      throw PDNSException("GSQLBackend get: "+e.txtReason());
    }
    if (row[1].empty())
        r.ttl = ::arg().asNum( "default-ttl" );
    else
        r.ttl=atol(row[1].c_str());
    if(!d_qname.empty())
      r.qname=d_qname;
    else
      r.qname=row[6];
    r.qtype=row[3];

    if (r.qtype==QType::MX || r.qtype==QType::SRV)
      r.content=row[2]+" "+row[0];
    else
      r.content=row[0];

    r.last_modified=0;

    if(d_dnssecQueries)
      r.auth = !row[7].empty() && row[7][0]=='1';
    else
      r.auth = 1;

    r.disabled = !row[5].empty() && row[5][0]=='1';

    r.domain_id=atoi(row[4].c_str());
    return true;
  }

  try {
    d_query_stmt->reset();
  } catch (SSqlException &e) {
      throw PDNSException("GSQLBackend get: "+e.txtReason());
  }
  d_query_stmt = NULL;
  return false;
}

bool GSQLBackend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **ddb)
{
  // check if we know the ip/ns couple in the database
  for(vector<DNSResourceRecord>::const_iterator i=nsset.begin();i!=nsset.end();++i) {
    try {
      d_SuperMasterInfoQuery_stmt->
        bind("ip", ip)->
        bind("nameserver", i->content)->
        execute()->
        getResult(d_result)->
        reset();
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
  try {
    d_InsertZoneQuery_stmt->
      bind("domain", toLower(domain))->
      execute()->
      reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to insert new domain '"+domain+"': "+ e.txtReason());
  }
  return true;
}

bool GSQLBackend::createSlaveDomain(const string &ip, const string &domain, const string &nameserver, const string &account)
{
  string name;
  string masters(ip);
  try {
    if (!nameserver.empty()) {
      // figure out all IP addresses for the master
      d_GetSuperMasterIPs_stmt->
        bind("nameserver", nameserver)->
        bind("account", account)->
        execute()->
        getResult(d_result)->
        reset();
      if (!d_result.empty()) {
        // collect all IP addresses
        vector<string> tmp;
        BOOST_FOREACH(SSqlStatement::row_t& row, d_result) {
          if (account == row[1])
            tmp.push_back(row[0]);
        }
        // set them as domain's masters, comma separated
        masters = boost::join(tmp, ", ");
      }
    }
    d_InsertSlaveZoneQuery_stmt->
      bind("domain", toLower(domain))->
      bind("masters", masters)->
      bind("account", account)->
      execute()->
      reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to insert new slave domain '"+domain+"': "+ e.txtReason());
  }
  return true;
}

bool GSQLBackend::deleteDomain(const string &domain)
{
  DomainInfo di;
  if (!getDomainInfo(domain, di)) {
    return false;
  }

  try {
    d_DeleteZoneQuery_stmt->
      bind("domain_id", di.id)->
      execute()->
      reset();
    d_ClearDomainAllMetadataQuery_stmt->
      bind("domain", toLower(domain))->
      execute()->
      reset();
    d_ClearDomainAllKeysQuery_stmt->
      bind("domain", toLower(domain))->
      execute()->
      reset();
    d_DeleteCommentsQuery_stmt->
      bind("domain_id", di.id)->
      execute()->
      reset();
    d_DeleteDomainQuery_stmt->
      bind("domain", toLower(domain))->
      execute()->
      reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to delete domain '"+domain+"': "+ e.txtReason());
  }
  return true;
}

void GSQLBackend::getAllDomains(vector<DomainInfo> *domains, bool include_disabled)
{
  DLOG(L<<"GSQLBackend retrieving all domains."<<endl);

  try {
    d_getAllDomainsQuery_stmt->
      bind("include_disabled", (int)include_disabled)->
      execute();

    SSqlStatement::row_t row;
    while (d_getAllDomainsQuery_stmt->hasNextRow()) {
      d_getAllDomainsQuery_stmt->nextRow(row);
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
    d_getAllDomainsQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("Database error trying to retrieve all domains:" + e.txtReason());
  }
}

bool GSQLBackend::replaceRRSet(uint32_t domain_id, const string& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  try {
    if (qt != QType::ANY) {
      d_DeleteRRSetQuery_stmt->
        bind("domain_id", domain_id)->
        bind("qname", qname)->
        bind("qtype", qt.getName())->
        execute()->
        reset();
    } else {
      d_DeleteNamesQuery_stmt->
        bind("domain_id", domain_id)->
        bind("qname", qname)->
        execute()->
        reset();
    }
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to delete RRSet: "+e.txtReason());
  }

  if (rrset.empty()) {
    try {
      d_DeleteCommentRRsetQuery_stmt->
        bind("domain_id", domain_id)->
        bind("qname", qname)->
        bind("qtype", qt.getName())->
        execute()->
        reset();
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
  int prio=0;
  string content(r.content);
  if (r.qtype == QType::MX || r.qtype == QType::SRV) {
    prio=atoi(content.c_str());
    string::size_type pos = content.find_first_not_of("0123456789");
    if(pos != string::npos)
      boost::erase_head(content, pos);
    trim_left(content);
  }

  try {
    if(d_dnssecQueries && ordername)
    {
      d_InsertRecordOrderQuery_stmt->
        bind("content",content)->
        bind("ttl",r.ttl)->
        bind("priority",prio)->
        bind("qtype",r.qtype.getName())->
        bind("domain_id",r.domain_id)->
        bind("disabled",r.disabled)->
        bind("qname",toLower(r.qname));
        if (ordername == NULL)
          d_InsertRecordOrderQuery_stmt->bindNull("ordername");
        else 
          d_InsertRecordOrderQuery_stmt->bind("ordername",*ordername);
        d_InsertRecordOrderQuery_stmt->
        bind("auth",r.auth)->
        execute()->
        reset();
    }
    else
    {
      d_InsertRecordQuery_stmt->
        bind("content",content)->
        bind("ttl",r.ttl)->
        bind("priority",prio)->
        bind("qtype",r.qtype.getName())-> 
        bind("domain_id",r.domain_id)->
        bind("disabled",r.disabled)->
        bind("qname",toLower(r.qname))->
        bind("auth", (r.auth || !d_dnssecQueries))->
        execute()->
        reset();
    }
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
    try {
      d_InsertEntQuery_stmt->
        bind("domain_id",domain_id)->
        bind("qname",toLower(nt.first))->
        bind("auth",(nt.second || !d_dnssecQueries))->
        execute()->
        reset();       
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

  string ordername;
  pair<string,bool> nt;

  BOOST_FOREACH(nt, nonterm) {
    try {
      if(narrow || !nt.second) {
        d_InsertEntQuery_stmt->
          bind("domain_id",domain_id)->
          bind("qname",toLower(nt.first))->
          bind("auth", nt.second)->
          execute()->
          reset();
      } else {
        ordername=toBase32Hex(hashQNameWithSalt(times, salt, nt.first));
        d_InsertEntOrderQuery_stmt->
          bind("domain_id",domain_id)->
          bind("qname",toLower(nt.first))->
          bind("ordername",toLower(ordername))->
          bind("auth",nt.second)->
          execute()->
          reset();
      }
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to feed empty non-terminal: "+e.txtReason());
    }
  }
  return true;
}

bool GSQLBackend::startTransaction(const string &domain, int domain_id)
{
  try {
    d_db->startTransaction();
    if(domain_id >= 0) {
      d_DeleteZoneQuery_stmt->
        bind("domain_id", domain_id)->
        execute()->
        reset();
    }
  }
  catch (SSqlException &e) {
    throw PDNSException("Database failed to start transaction: "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::commitTransaction()
{
  try {
    d_db->commit();
  }
  catch (SSqlException &e) {
    throw PDNSException("Database failed to commit transaction: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::abortTransaction()
{
  try {
    d_db->rollback();
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
  
  try {
    d_ZoneLastChangeQuery_stmt->
      bind("domain_id", sd.domain_id)->
      execute()->
      getResult(d_result)->
      reset();
  }
  catch (const SSqlException& e) {
    //DLOG(L<<"GSQLBackend unable to calculate SOA serial: " << e.txtReason()<<endl);
    return false;
  }
 
  if (!d_result.empty()) {
    serial = atol(d_result[0][0].c_str());
    return true;
  }

  return false;
}

bool GSQLBackend::listComments(const uint32_t domain_id)
{
  try {
    d_query_stmt = d_ListCommentsQuery_stmt;
    d_query_stmt->
      bind("domain_id", domain_id)->
      execute();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend list comments query: "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::getComment(Comment& comment)
{
  SSqlStatement::row_t row;

  if (!d_query_stmt->hasNextRow()) {
    try {
      d_query_stmt->reset();
    } catch(SSqlException &e) {
      throw PDNSException("GSQLBackend comment get: "+e.txtReason());
    }
    d_query_stmt = NULL;
    return false;
  }

  try {
    d_query_stmt->nextRow(row);
  } catch(SSqlException &e) {
    throw PDNSException("GSQLBackend comment get: "+e.txtReason());
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
  try {
    d_InsertCommentQuery_stmt->
      bind("domain_id",comment.domain_id)->
      bind("qname",toLower(comment.qname))->
      bind("qtype",comment.qtype.getName())->
      bind("modified_at",comment.modified_at)->
      bind("account",comment.account)->
      bind("content",comment.content)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to feed comment: "+e.txtReason());
  }
}

bool GSQLBackend::replaceComments(const uint32_t domain_id, const string& qname, const QType& qt, const vector<Comment>& comments)
{
  try {
    d_DeleteCommentRRsetQuery_stmt->
      bind("domain_id",domain_id)->
      bind("qname",toLower(qname))->
      bind("qtype",qt.getName())->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to delete comment: "+e.txtReason());
  }

  BOOST_FOREACH(const Comment& comment, comments) {
    feedComment(comment);
  }

  return true;
}

SSqlStatement::~SSqlStatement() { 
// make sure vtable won't break 
}
