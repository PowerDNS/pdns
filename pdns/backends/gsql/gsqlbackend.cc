/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "gsqlbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/base32.hh"
#include "pdns/dnssecinfra.hh"
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <boost/format.hpp>
#include <boost/scoped_ptr.hpp>

#define ASSERT_ROW_COLUMNS(query, row, num) { if (row.size() != num) { throw PDNSException(std::string(query) + " returned wrong number of columns, expected "  #num  ", got " + std::to_string(row.size())); } }

GSQLBackend::GSQLBackend(const string &mode, const string &suffix)
{
  setArgPrefix(mode+suffix);
  d_db = nullptr;
  d_logprefix="["+mode+"Backend"+suffix+"] ";

  try {
    d_dnssecQueries = mustDo("dnssec");
  }
  catch (const ArgException&) {
    d_dnssecQueries = false;
  }

  try {
    d_upgradeContent = ::arg().mustDo("upgrade-unknown-types");
  }
  catch (const ArgException&) {
    d_upgradeContent = false;
  }

  d_NoIdQuery=getArg("basic-query");
  d_IdQuery=getArg("id-query");
  d_ANYNoIdQuery=getArg("any-query");
  d_ANYIdQuery=getArg("any-id-query");

  d_listQuery=getArg("list-query");
  d_listSubZoneQuery=getArg("list-subzone-query");

  d_InfoOfDomainsZoneQuery=getArg("info-zone-query");
  d_InfoOfAllSlaveDomainsQuery=getArg("info-all-slaves-query");
  d_SuperMasterInfoQuery=getArg("supermaster-query");
  d_GetSuperMasterIPs=getArg("supermaster-name-to-ips");
  d_AddSuperMaster=getArg("supermaster-add");
  d_RemoveAutoPrimaryQuery=getArg("autoprimary-remove");
  d_ListAutoPrimariesQuery=getArg("list-autoprimaries");
  d_InsertZoneQuery=getArg("insert-zone-query");
  d_InsertRecordQuery=getArg("insert-record-query");
  d_UpdateMasterOfZoneQuery=getArg("update-master-query");
  d_UpdateKindOfZoneQuery=getArg("update-kind-query");
  d_UpdateSerialOfZoneQuery=getArg("update-serial-query");
  d_UpdateLastCheckOfZoneQuery=getArg("update-lastcheck-query");
  d_UpdateOptionsOfZoneQuery = getArg("update-options-query");
  d_UpdateCatalogOfZoneQuery = getArg("update-catalog-query");
  d_UpdateAccountOfZoneQuery=getArg("update-account-query");
  d_InfoOfAllMasterDomainsQuery=getArg("info-all-master-query");
  d_InfoProducerMembersQuery = getArg("info-producer-members-query");
  d_InfoConsumerMembersQuery = getArg("info-consumer-members-query");
  d_DeleteDomainQuery=getArg("delete-domain-query");
  d_DeleteZoneQuery=getArg("delete-zone-query");
  d_DeleteRRSetQuery=getArg("delete-rrset-query");
  d_DeleteNamesQuery=getArg("delete-names-query");
  d_getAllDomainsQuery=getArg("get-all-domains-query");

  d_InsertEmptyNonTerminalOrderQuery=getArg("insert-empty-non-terminal-order-query");
  d_DeleteEmptyNonTerminalQuery = getArg("delete-empty-non-terminal-query");
  d_RemoveEmptyNonTerminalsFromZoneQuery = getArg("remove-empty-non-terminals-from-zone-query");

  d_ListCommentsQuery = getArg("list-comments-query");
  d_InsertCommentQuery = getArg("insert-comment-query");
  d_DeleteCommentRRsetQuery = getArg("delete-comment-rrset-query");
  d_DeleteCommentsQuery = getArg("delete-comments-query");

  d_firstOrderQuery = getArg("get-order-first-query");
  d_beforeOrderQuery = getArg("get-order-before-query");
  d_afterOrderQuery = getArg("get-order-after-query");
  d_lastOrderQuery = getArg("get-order-last-query");

  d_updateOrderNameAndAuthQuery = getArg("update-ordername-and-auth-query");
  d_updateOrderNameAndAuthTypeQuery = getArg("update-ordername-and-auth-type-query");
  d_nullifyOrderNameAndUpdateAuthQuery = getArg("nullify-ordername-and-update-auth-query");
  d_nullifyOrderNameAndUpdateAuthTypeQuery = getArg("nullify-ordername-and-update-auth-type-query");

  d_AddDomainKeyQuery = getArg("add-domain-key-query");
  d_GetLastInsertedKeyIdQuery = getArg("get-last-inserted-key-id-query");
  d_ListDomainKeysQuery = getArg("list-domain-keys-query");

  d_GetAllDomainMetadataQuery = getArg("get-all-domain-metadata-query");
  d_GetDomainMetadataQuery = getArg("get-domain-metadata-query");
  d_ClearDomainMetadataQuery = getArg("clear-domain-metadata-query");
  d_ClearDomainAllMetadataQuery = getArg("clear-domain-all-metadata-query");
  d_SetDomainMetadataQuery = getArg("set-domain-metadata-query");

  d_ActivateDomainKeyQuery = getArg("activate-domain-key-query");
  d_DeactivateDomainKeyQuery = getArg("deactivate-domain-key-query");
  d_PublishDomainKeyQuery = getArg("publish-domain-key-query");
  d_UnpublishDomainKeyQuery = getArg("unpublish-domain-key-query");
  d_RemoveDomainKeyQuery = getArg("remove-domain-key-query");
  d_ClearDomainAllKeysQuery = getArg("clear-domain-all-keys-query");

  d_getTSIGKeyQuery = getArg("get-tsig-key-query");
  d_setTSIGKeyQuery = getArg("set-tsig-key-query");
  d_deleteTSIGKeyQuery = getArg("delete-tsig-key-query");
  d_getTSIGKeysQuery = getArg("get-tsig-keys-query");

  d_SearchRecordsQuery = getArg("search-records-query");
  d_SearchCommentsQuery = getArg("search-comments-query");

  d_query_stmt = nullptr;
  d_NoIdQuery_stmt = nullptr;
  d_IdQuery_stmt = nullptr;
  d_ANYNoIdQuery_stmt = nullptr;
  d_ANYIdQuery_stmt = nullptr;
  d_listQuery_stmt = nullptr;
  d_listSubZoneQuery_stmt = nullptr;
  d_InfoOfDomainsZoneQuery_stmt = nullptr;
  d_InfoOfAllSlaveDomainsQuery_stmt = nullptr;
  d_SuperMasterInfoQuery_stmt = nullptr;
  d_GetSuperMasterIPs_stmt = nullptr;
  d_AddSuperMaster_stmt = nullptr;
  d_RemoveAutoPrimary_stmt = nullptr;
  d_ListAutoPrimaries_stmt = nullptr;
  d_InsertZoneQuery_stmt = nullptr;
  d_InsertRecordQuery_stmt = nullptr;
  d_InsertEmptyNonTerminalOrderQuery_stmt = nullptr;
  d_UpdateMasterOfZoneQuery_stmt = nullptr;
  d_UpdateKindOfZoneQuery_stmt = nullptr;
  d_UpdateSerialOfZoneQuery_stmt = nullptr;
  d_UpdateLastCheckOfZoneQuery_stmt = nullptr;
  d_UpdateOptionsOfZoneQuery_stmt = nullptr;
  d_UpdateCatalogOfZoneQuery_stmt = nullptr;
  d_UpdateAccountOfZoneQuery_stmt = nullptr;
  d_InfoOfAllMasterDomainsQuery_stmt = nullptr;
  d_InfoProducerMembersQuery_stmt = nullptr;
  d_InfoConsumerMembersQuery_stmt = nullptr;
  d_DeleteDomainQuery_stmt = nullptr;
  d_DeleteZoneQuery_stmt = nullptr;
  d_DeleteRRSetQuery_stmt = nullptr;
  d_DeleteNamesQuery_stmt = nullptr;
  d_firstOrderQuery_stmt = nullptr;
  d_beforeOrderQuery_stmt = nullptr;
  d_afterOrderQuery_stmt = nullptr;
  d_lastOrderQuery_stmt = nullptr;
  d_updateOrderNameAndAuthQuery_stmt = nullptr;
  d_updateOrderNameAndAuthTypeQuery_stmt = nullptr;
  d_nullifyOrderNameAndUpdateAuthQuery_stmt = nullptr;
  d_nullifyOrderNameAndUpdateAuthTypeQuery_stmt = nullptr;
  d_RemoveEmptyNonTerminalsFromZoneQuery_stmt = nullptr;
  d_DeleteEmptyNonTerminalQuery_stmt = nullptr;
  d_AddDomainKeyQuery_stmt = nullptr;
  d_GetLastInsertedKeyIdQuery_stmt = nullptr;
  d_ListDomainKeysQuery_stmt = nullptr;
  d_GetAllDomainMetadataQuery_stmt = nullptr;
  d_GetDomainMetadataQuery_stmt = nullptr;
  d_ClearDomainMetadataQuery_stmt = nullptr;
  d_ClearDomainAllMetadataQuery_stmt = nullptr;
  d_SetDomainMetadataQuery_stmt = nullptr;
  d_RemoveDomainKeyQuery_stmt = nullptr;
  d_ActivateDomainKeyQuery_stmt = nullptr;
  d_DeactivateDomainKeyQuery_stmt = nullptr;
  d_PublishDomainKeyQuery_stmt = nullptr;
  d_UnpublishDomainKeyQuery_stmt = nullptr;
  d_ClearDomainAllKeysQuery_stmt = nullptr;
  d_getTSIGKeyQuery_stmt = nullptr;
  d_setTSIGKeyQuery_stmt = nullptr;
  d_deleteTSIGKeyQuery_stmt = nullptr;
  d_getTSIGKeysQuery_stmt = nullptr;
  d_getAllDomainsQuery_stmt = nullptr;
  d_ListCommentsQuery_stmt = nullptr;
  d_InsertCommentQuery_stmt = nullptr;
  d_DeleteCommentRRsetQuery_stmt = nullptr;
  d_DeleteCommentsQuery_stmt = nullptr;
  d_SearchRecordsQuery_stmt = nullptr;
  d_SearchCommentsQuery_stmt = nullptr;
}

void GSQLBackend::setNotified(uint32_t domain_id, uint32_t serial)
{
  try {
    reconnectIfNeeded();

    d_UpdateSerialOfZoneQuery_stmt->
      bind("serial", serial)->
      bind("domain_id", domain_id)->
      execute()->
      reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to refresh domain_id "+std::to_string(domain_id)+": "+e.txtReason());
  }
}

void GSQLBackend::setLastCheck(uint32_t domain_id, time_t lastcheck)
{
  try {
    reconnectIfNeeded();

    d_UpdateLastCheckOfZoneQuery_stmt->bind("last_check", lastcheck)->bind("domain_id", domain_id)->execute()->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to update last_check for domain_id " + std::to_string(domain_id) + ": " + e.txtReason());
  }
}

void GSQLBackend::setStale(uint32_t domain_id)
{
  setLastCheck(domain_id, 0);
}

void GSQLBackend::setFresh(uint32_t domain_id)
{
  setLastCheck(domain_id, time(nullptr));
}

bool GSQLBackend::setMasters(const DNSName &domain, const vector<ComboAddress> &masters)
{
  vector<string> masters_s;
  masters_s.reserve(masters.size());
  for (const auto& master : masters) {
    masters_s.push_back(master.toStringWithPortExcept(53));
  }

  auto tmp = boost::join(masters_s, ", ");

  try {
    reconnectIfNeeded();

    d_UpdateMasterOfZoneQuery_stmt->
      bind("master", tmp)->
      bind("domain", domain)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set masters of domain '"+domain.toLogString()+"' to " + tmp + ": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::setKind(const DNSName &domain, const DomainInfo::DomainKind kind)
{
  try {
    reconnectIfNeeded();

    d_UpdateKindOfZoneQuery_stmt->
      bind("kind", toUpper(DomainInfo::getKindString(kind)))->
      bind("domain", domain)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set kind of domain '"+domain.toLogString()+"' to " + toUpper(DomainInfo::getKindString(kind)) + ": "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::setOptions(const DNSName& domain, const string& options)
{
  try {
    reconnectIfNeeded();

    // clang-format off
    d_UpdateOptionsOfZoneQuery_stmt->
      bind("options", options)->
      bind("domain", domain)->
      execute()->
      reset();
    // clang-format on
  }
  catch (SSqlException& e) {
    throw PDNSException("GSQLBackend unable to set options of domain '" + domain.toLogString() + "' to '" + options + "': " + e.txtReason());
  }
  return true;
}

bool GSQLBackend::setCatalog(const DNSName& domain, const DNSName& catalog)
{
  try {
    reconnectIfNeeded();

    // clang-format off
    d_UpdateCatalogOfZoneQuery_stmt->
      bind("catalog", catalog)->
      bind("domain", domain)->
      execute()->
      reset();
    // clang-format on
  }
  catch (SSqlException& e) {
    throw PDNSException("GSQLBackend unable to set catalog of domain '" + domain.toLogString() + "' to '" + catalog.toLogString() + "': " + e.txtReason());
  }
  return true;
}

bool GSQLBackend::setAccount(const DNSName &domain, const string &account)
{
  try {
    reconnectIfNeeded();

    d_UpdateAccountOfZoneQuery_stmt->
            bind("account", account)->
            bind("domain", domain)->
            execute()->
            reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set account of domain '"+domain.toLogString()+"' to '" + account + "': "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial)
{
  /* fill DomainInfo from database info:
     id,name,master IP(s),last_check,notified_serial,type,account */
  try {
    reconnectIfNeeded();

    d_InfoOfDomainsZoneQuery_stmt->
      bind("domain", domain)->
      execute()->
      getResult(d_result)->
      reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve information about domain '" + domain.toLogString() + "': "+e.txtReason());
  }

  int numanswers=d_result.size();
  if(!numanswers)
    return false;

  ASSERT_ROW_COLUMNS("info-zone-query", d_result[0], 9);

  pdns::checked_stoi_into(di.id, d_result[0][0]);
  try {
    di.zone=DNSName(d_result[0][1]);
    di.catalog = (!d_result[0][7].empty() ? DNSName(d_result[0][7]) : DNSName());
  } catch (...) {
    return false;
  }
  string type=d_result[0][5];
  di.options = d_result[0][6];
  di.account = d_result[0][8];
  di.kind = DomainInfo::stringToKind(type);

  vector<string> masters;
  stringtok(masters, d_result[0][2], " ,\t");
  for(const auto& m : masters)
    di.masters.emplace_back(m, 53);
  pdns::checked_stoi_into(di.last_check, d_result[0][3]);
  pdns::checked_stoi_into(di.notified_serial, d_result[0][4]);
  di.backend=this;

  di.serial = 0;
  if(getSerial) {
    try {
      SOAData sd;
      if(!getSOA(domain, sd))
        g_log<<Logger::Notice<<"No serial for '"<<domain<<"' found - zone is missing?"<<endl;
      else
        di.serial = sd.serial;
    }
    catch(PDNSException &ae){
      g_log<<Logger::Error<<"Error retrieving serial for '"<<domain<<"': "<<ae.reason<<endl;
    }
  }

  return true;
}

void GSQLBackend::getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains)
{
  /*
    list all domains that need refreshing for which we are secondary, and insert into
    unfreshDomains: id, name, master, serial
  */

  try {
    reconnectIfNeeded();

    // clang-format off
    d_InfoOfAllSlaveDomainsQuery_stmt->
      execute()->
      getResult(d_result)->
      reset();
    // clang-format on
  }
  catch (SSqlException &e) {
    throw PDNSException(std::string(__PRETTY_FUNCTION__) + " unable to retrieve list of slave domains: " + e.txtReason());
  }

  SOAData sd;
  DomainInfo di;
  vector<string> masters;

  unfreshDomains->reserve(d_result.size());
  for (const auto& row : d_result) { // id, name, type, master, last_check, catalog, content
    ASSERT_ROW_COLUMNS("info-all-slaves-query", row, 6);

    try {
      di.zone = DNSName(row[1]);
    }
    catch (const std::runtime_error& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " zone name '" << row[1] << "' is not a valid DNS name: " << e.what() << endl;
      continue;
    }
    catch (PDNSException& ae) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " zone name '" << row[1] << "' is not a valid DNS name: " << ae.reason << endl;
      continue;
    }

    if (!row[5].empty()) {
      try {
        fillSOAData(row[5], sd);
      }
      catch (const std::exception& exp) {
        g_log << Logger::Warning << __PRETTY_FUNCTION__ << " error while parsing SOA data for zone '" << di.zone << "': " << exp.what() << endl;
        continue;
      }
      catch (...) {
        g_log << Logger::Warning << __PRETTY_FUNCTION__ << " error while parsing SOA data for zone '" << di.zone << endl;
        continue;
      }

      uint32_t last_check;
      try {
        pdns::checked_stoi_into(last_check, row[4]);
      }
      catch (const std::exception& e) {
        g_log << Logger::Warning << __PRETTY_FUNCTION__ << " could not convert last_check '" << row[4] << "' for zone '" << di.zone << "' into an integer: " << e.what() << endl;
        continue;
      }

      if (static_cast<time_t>(last_check + sd.refresh) > time(nullptr)) { // still fresh
        continue;
      }
      di.serial = sd.serial;
    }

    try {
      pdns::checked_stoi_into(di.id, row[0]);
    } catch (const std::exception &e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " could not convert id '" << row[0] << "' for zone '" << di.zone << "' into an integer: " << e.what() << endl;
      continue;
    }

    di.masters.clear();
    masters.clear();
    stringtok(masters, row[3], ", \t");
    for(const auto& m : masters) {
      try {
        di.masters.emplace_back(m, 53);
      } catch(const PDNSException &e) {
        g_log << Logger::Warning << __PRETTY_FUNCTION__ << " could not parse master address '" << m << "' for zone '" << di.zone << "': " << e.reason << endl;
      }
    }
    if (di.masters.empty()) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " no masters for secondary zone '" << di.zone << "' found in the database" << endl;
      continue;
    }

    if (pdns_iequals(row[2], "SLAVE")) {
      di.kind = DomainInfo::Slave;
    }
    else if (pdns_iequals(row[2], "CONSUMER")) {
      di.kind = DomainInfo::Consumer;
    }
    else {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << "type '" << row[2] << "' for zone '" << di.zone << "' is no secondary type" << endl;
    }

    di.backend = this;
    unfreshDomains->emplace_back(di);
  }
}

void GSQLBackend::getUpdatedMasters(vector<DomainInfo>& updatedDomains, std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes)
{
  /*
    list all domains that need notifications for which we are promary, and insert into
    updatedDomains: id, name, notified_serial, serial
  */

  try {
    reconnectIfNeeded();

    // clang-format off
    d_InfoOfAllMasterDomainsQuery_stmt->
      execute()->
      getResult(d_result)->
      reset();
    // clang-format on
  }
  catch(SSqlException &e) {
    throw PDNSException(std::string(__PRETTY_FUNCTION__) + " unable to retrieve list of master domains: " + e.txtReason());
  }

  SOAData sd;
  DomainInfo di;
  CatalogInfo ci;

  updatedDomains.reserve(d_result.size());
  for (const auto& row : d_result) { // id, name, type, notified_serial, options, catalog, content
    ASSERT_ROW_COLUMNS("info-all-master-query", row, 7);

    di.backend = this;

    try {
      pdns::checked_stoi_into(di.id, row[0]);
    }
    catch (const std::exception& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " could not convert id '" << row[0] << "' for zone '" << di.zone << "' into an integer: " << e.what() << endl;
      continue;
    }

    try {
      di.zone = DNSName(row[1]);
    }
    catch (const std::runtime_error& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " zone name '" << row[1] << "' is not a valid DNS name: " << e.what() << endl;
      continue;
    }
    catch (PDNSException& ae) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " zone name '" << row[1] << "' is not a valid DNS name: " << ae.reason << endl;
      continue;
    }

    try {
      di.catalog = DNSName(row[5]);
    }
    catch (const std::runtime_error& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " zone name '" << row[5] << "' is not a valid DNS name: " << e.what() << endl;
      continue;
    }
    catch (PDNSException& ae) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " zone name '" << row[5] << "' is not a valid DNS name: " << ae.reason << endl;
      continue;
    }

    if (pdns_iequals(row[2], "PRODUCER")) {
      catalogs.insert(di.zone);
      catalogHashes[di.zone].process("\0");
      continue; // Producer fresness check is performed elsewhere
    }
    else if (!pdns_iequals(row[2], "MASTER")) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " type '" << row[2] << "' for zone '" << di.zone << "' is no primary type" << endl;
    }

    try {
      if (!row[5].empty()) {
        ci.fromJson(row[4], CatalogInfo::CatalogType::Producer);
        ci.updateHash(catalogHashes, di);
      }
    }
    catch (const std::exception& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " catalog hash update failed'" << row[4] << "' for zone '" << di.zone << "' member of '" << di.catalog << "': " << e.what() << endl;
      continue;
    }

    try {
      pdns::checked_stoi_into(di.notified_serial, row[3]);
    }
    catch (const std::exception& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " could not convert notified_serial '" << row[4] << "' for zone '" << di.zone << "' into an integer: " << e.what() << endl;
      continue;
    }

    try {
      fillSOAData(row[6], sd);
    }
    catch (const std::exception& exp) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " error while parsing SOA content '" << row[6] << "' for zone '" << di.zone << "': " << exp.what() << endl;
      continue;
    }
    catch (...) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " error while parsing SOA content '" << row[6] << "' for zone '" << di.zone << endl;
      continue;
    }

    if (di.notified_serial != sd.serial) {
      di.kind = DomainInfo::Master;
      di.serial = sd.serial;
      di.catalog.clear();

      updatedDomains.emplace_back(di);
    }
  }
}

bool GSQLBackend::getCatalogMembers(const DNSName& catalog, vector<CatalogInfo>& members, CatalogInfo::CatalogType type)
{
  try {
    reconnectIfNeeded();

    if (type == CatalogInfo::CatalogType::Producer) {
      // clang-format off
      d_InfoProducerMembersQuery_stmt->
        bind("catalog", catalog)->
        execute()->
        getResult(d_result)->
        reset();
      // clang-format on
    }
    else if (type == CatalogInfo::CatalogType::Consumer) {
      // clang-format off
      d_InfoConsumerMembersQuery_stmt->
        bind("catalog", catalog)->
        execute()->
        getResult(d_result)->
        reset();
      // clang-format on
    }
    else {
      PDNSException(std::string(__PRETTY_FUNCTION__) + " unknown type '" + CatalogInfo::getTypeString(type) + "'");
    }
  }
  catch (SSqlException& e) {
    throw PDNSException(std::string(__PRETTY_FUNCTION__) + " unable to retrieve list of member zones: " + e.txtReason());
  }

  members.reserve(d_result.size());
  for (const auto& row : d_result) { // id, zone, options, [master]
    if (type == CatalogInfo::CatalogType::Producer) {
      ASSERT_ROW_COLUMNS("info-producer/consumer-members-query", row, 3);
    }
    else {
      ASSERT_ROW_COLUMNS("info-producer/consumer-members-query", row, 4);
    }

    CatalogInfo ci;

    try {
      ci.d_zone = DNSName(row[1]);
    }
    catch (const std::runtime_error& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " zone name '" << row[1] << "' is not a valid DNS name: " << e.what() << endl;
      members.clear();
      return false;
    }
    catch (PDNSException& ae) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " zone name '" << row[1] << "' is not a valid DNS name: " << ae.reason << endl;
      members.clear();
      return false;
    }

    try {
      pdns::checked_stoi_into(ci.d_id, row[0]);
    }
    catch (const std::exception& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " could not convert id '" << row[0] << "' for zone '" << ci.d_zone << "' into an integer: " << e.what() << endl;
      members.clear();
      return false;
    }

    try {
      ci.fromJson(row[2], type);
    }
    catch (const std::runtime_error& e) {
      g_log << Logger::Warning << __PRETTY_FUNCTION__ << " options '" << row[2] << "' for zone '" << ci.d_zone << "' is no valid JSON: " << e.what() << endl;
      members.clear();
      return false;
    }

    if (row.size() >= 4) { // Consumer only
      vector<string> masters;
      stringtok(masters, row[3], ", \t");
      for (const auto& m : masters) {
        try {
          ci.d_primaries.emplace_back(m, 53);
        }
        catch (const PDNSException& e) {
          g_log << Logger::Warning << __PRETTY_FUNCTION__ << " could not parse master address '" << m << "' for zone '" << ci.d_zone << "': " << e.reason << endl;
          members.clear();
          return false;
        }
      }
    }

    members.emplace_back(ci);
  }
  return true;
}

bool GSQLBackend::updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype)
{
  if(!d_dnssecQueries)
    return false;

  if (!ordername.empty()) {
    if (qtype == QType::ANY) {
      try {
        reconnectIfNeeded();

        d_updateOrderNameAndAuthQuery_stmt->
          bind("ordername", ordername.labelReverse().toString(" ", false))->
          bind("auth", auth)->
          bind("domain_id", domain_id)->
          bind("qname", qname)->
          execute()->
          reset();
      }
      catch(SSqlException &e) {
        throw PDNSException("GSQLBackend unable to update ordername and auth for " + qname.toLogString() + " for domain_id "+std::to_string(domain_id)+", domain name '" + qname.toLogString() + "': "+e.txtReason());
      }
    } else {
      try {
        reconnectIfNeeded();

        d_updateOrderNameAndAuthTypeQuery_stmt->
          bind("ordername", ordername.labelReverse().toString(" ", false))->
          bind("auth", auth)->
          bind("domain_id", domain_id)->
          bind("qname", qname)->
          bind("qtype", QType(qtype).toString())->
          execute()->
          reset();
      }
      catch(SSqlException &e) {
        throw PDNSException("GSQLBackend unable to update ordername and auth for " + qname.toLogString() + "|" + QType(qtype).toString() + " for domain_id "+std::to_string(domain_id)+": "+e.txtReason());
      }
    }
  } else {
    if (qtype == QType::ANY) {
      reconnectIfNeeded();

      try {
        d_nullifyOrderNameAndUpdateAuthQuery_stmt->
          bind("auth", auth)->
          bind("domain_id", domain_id)->
          bind("qname", qname)->
          execute()->
          reset();
      }
      catch(SSqlException &e) {
        throw PDNSException("GSQLBackend unable to nullify ordername and update auth for " + qname.toLogString() + " for domain_id "+std::to_string(domain_id)+": "+e.txtReason());
      }
    } else {
      try {
        reconnectIfNeeded();

        d_nullifyOrderNameAndUpdateAuthTypeQuery_stmt->
          bind("auth", auth)->
          bind("domain_id", domain_id)->
          bind("qname", qname)->
          bind("qtype", QType(qtype).toString())->
          execute()->
          reset();
      }
      catch(SSqlException &e) {
        throw PDNSException("GSQLBackend unable to nullify ordername and update auth for " + qname.toLogString() + "|" + QType(qtype).toString() + " for domain_id "+std::to_string(domain_id)+": "+e.txtReason());
      }
    }
  }
  return true;
}

bool GSQLBackend::updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove)
{
  if(remove) {
    try {
      reconnectIfNeeded();

      d_RemoveEmptyNonTerminalsFromZoneQuery_stmt->
        bind("domain_id", domain_id)->
        execute()->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to delete empty non-terminal records from domain_id "+std::to_string(domain_id)+": "+e.txtReason());
    }
  }
  else
  {
    for(const auto& qname: erase) {
      try {
        reconnectIfNeeded();

        d_DeleteEmptyNonTerminalQuery_stmt->
          bind("domain_id", domain_id)->
          bind("qname", qname)->
          execute()->
          reset();
      }
      catch (SSqlException &e) {
        throw PDNSException("GSQLBackend unable to delete empty non-terminal rr '"+qname.toLogString()+"' from domain_id "+std::to_string(domain_id)+": "+e.txtReason());
      }
    }
  }

  for(const auto& qname: insert) {
    try {
      reconnectIfNeeded();

      d_InsertEmptyNonTerminalOrderQuery_stmt->
        bind("domain_id", domain_id)->
        bind("qname", qname)->
        bindNull("ordername")->
        bind("auth", true)->
        execute()->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to insert empty non-terminal rr '"+qname.toLogString()+"' in domain_id "+std::to_string(domain_id)+": "+e.txtReason());
    }
  }

  return true;
}

bool GSQLBackend::doesDNSSEC()
{
    return d_dnssecQueries;
}

bool GSQLBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
  if(!d_dnssecQueries)
    return false;
  after.clear();

  SSqlStatement::row_t row;
  try {
    reconnectIfNeeded();

    d_afterOrderQuery_stmt->
      bind("ordername", qname.labelReverse().toString(" ", false))->
      bind("domain_id", id)->
      execute();
    while(d_afterOrderQuery_stmt->hasNextRow()) {
      d_afterOrderQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("get-order-after-query", row, 1);
      if(! row[0].empty()) { // Hack because NULL values are passed on as empty strings
        after=DNSName(boost::replace_all_copy(row[0]," ",".")).labelReverse();
      }
    }
    d_afterOrderQuery_stmt->reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to find before/after (after) for domain_id "+std::to_string(id)+" and qname '"+ qname.toLogString() +"': "+e.txtReason());
  }

  if(after.empty()) {
    try {
      reconnectIfNeeded();

      d_firstOrderQuery_stmt->
        bind("domain_id", id)->
        execute();
      while(d_firstOrderQuery_stmt->hasNextRow()) {
        d_firstOrderQuery_stmt->nextRow(row);
        ASSERT_ROW_COLUMNS("get-order-first-query", row, 1);
        after=DNSName(boost::replace_all_copy(row[0]," ",".")).labelReverse();
      }
      d_firstOrderQuery_stmt->reset();
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (first) for domain_id "+std::to_string(id)+" and qname '"+ qname.toLogString() + "': "+e.txtReason());
    }
  }

  if (before.empty()) {
    unhashed.clear();

    try {
      reconnectIfNeeded();

      d_beforeOrderQuery_stmt->
        bind("ordername", qname.labelReverse().toString(" ", false))->
        bind("domain_id", id)->
        execute();
      while(d_beforeOrderQuery_stmt->hasNextRow()) {
        d_beforeOrderQuery_stmt->nextRow(row);
        ASSERT_ROW_COLUMNS("get-order-before-query", row, 2);
        before=DNSName(boost::replace_all_copy(row[0]," ",".")).labelReverse();
        try {
          unhashed=DNSName(row[1]);
        } catch (...) {
          continue;
        }
      }
      d_beforeOrderQuery_stmt->reset();
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (before) for domain_id "+std::to_string(id)+" and qname '"+ qname.toLogString() + ": "+e.txtReason());
    }

    if(! unhashed.empty())
    {
      // cerr<<"unhashed="<<unhashed<<",before="<<before<<", after="<<after<<endl;
      return true;
    }

    try {
      reconnectIfNeeded();

      d_lastOrderQuery_stmt->
        bind("domain_id", id)->
        execute();
      while(d_lastOrderQuery_stmt->hasNextRow()) {
        d_lastOrderQuery_stmt->nextRow(row);
        ASSERT_ROW_COLUMNS("get-order-last-query", row, 2);
        before=DNSName(boost::replace_all_copy(row[0]," ",".")).labelReverse();
        try {
          unhashed=DNSName(row[1]);
        } catch (...) {
          continue;
        }
      }
      d_lastOrderQuery_stmt->reset();
    }
    catch(SSqlException &e) {
      throw PDNSException("GSQLBackend unable to find before/after (last) for domain_id "+std::to_string(id)+" and qname '"+ qname.toLogString() + ": "+e.txtReason());
    }
  } else {
    before=qname;
  }

  return true;
}

bool GSQLBackend::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id)
{
  if(!d_dnssecQueries)
    return false;

  try {
    reconnectIfNeeded();

    d_AddDomainKeyQuery_stmt->
      bind("flags", key.flags)->
      bind("active", key.active)->
      bind("published", key.published)->
      bind("content", key.content)->
      bind("domain", name)->
      execute();

    if (d_AddDomainKeyQuery_stmt->hasNextRow()) {
      SSqlStatement::row_t row;
      d_AddDomainKeyQuery_stmt->nextRow(row);
      id = std::stoi(row[0]);
      d_AddDomainKeyQuery_stmt->reset();
      return true;
    } else {
      d_AddDomainKeyQuery_stmt->reset();
    }
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to store key for domain '"+ name.toLogString() + "': "+e.txtReason());
  }

  try {
    reconnectIfNeeded();

    d_GetLastInsertedKeyIdQuery_stmt->execute();
    if (!d_GetLastInsertedKeyIdQuery_stmt->hasNextRow()) {
      id = -2;
      return true;
    }
    SSqlStatement::row_t row;
    d_GetLastInsertedKeyIdQuery_stmt->nextRow(row);
    ASSERT_ROW_COLUMNS("get-last-inserted-key-id-query", row, 1);
    id = std::stoi(row[0]);
    d_GetLastInsertedKeyIdQuery_stmt->reset();
    return true;
  }
  catch (SSqlException &e) {
    id = -2;
    return true;
  }
}

bool GSQLBackend::activateDomainKey(const DNSName& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return false;

  try {
    reconnectIfNeeded();

    d_ActivateDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to activate key with id "+ std::to_string(id) + " for domain '" + name.toLogString() + "': "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::deactivateDomainKey(const DNSName& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return false;

  try {
    reconnectIfNeeded();

    d_DeactivateDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to deactivate key with id "+ std::to_string(id) + " for domain '" + name.toLogString() + "': "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::publishDomainKey(const DNSName& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return false;

  try {
    reconnectIfNeeded();

    d_PublishDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to publish key with id "+ std::to_string(id) + " for domain '" + name.toLogString() + "': "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::unpublishDomainKey(const DNSName& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return false;

  try {
    reconnectIfNeeded();

    d_UnpublishDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to unpublish key with id "+ std::to_string(id) + " for domain '" + name.toLogString() + "': "+e.txtReason());
  }
  return true;
}



bool GSQLBackend::removeDomainKey(const DNSName& name, unsigned int id)
{
  if(!d_dnssecQueries)
    return false;

  try {
    reconnectIfNeeded();

    d_RemoveDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to remove key with id "+ std::to_string(id) + " for domain '" + name.toLogString() + "': "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getTSIGKey(const DNSName& name, DNSName& algorithm, string& content)
{
  try {
    reconnectIfNeeded();

    d_getTSIGKeyQuery_stmt->
      bind("key_name", name)->
      execute();

    SSqlStatement::row_t row;

    while(d_getTSIGKeyQuery_stmt->hasNextRow()) {
      d_getTSIGKeyQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("get-tsig-key-query", row, 2);
      try{
        if (algorithm.empty() || algorithm == DNSName(row[0])) {
          algorithm = DNSName(row[0]);
          content = row[1];
        }
      } catch (...) {}
    }

    d_getTSIGKeyQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve TSIG key with name '" + name.toLogString() + "': "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content)
{
  try {
    reconnectIfNeeded();

    d_setTSIGKeyQuery_stmt->
      bind("key_name", name)->
      bind("algorithm", algorithm)->
      bind("content", content)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to store TSIG key with name '" + name.toLogString() + "' and algorithm '" + algorithm.toString() + "': "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::deleteTSIGKey(const DNSName& name)
{
  try {
    reconnectIfNeeded();

    d_deleteTSIGKeyQuery_stmt->
      bind("key_name", name)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to delete TSIG key with name '" + name.toLogString() + "': "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{
  try {
    reconnectIfNeeded();

    d_getTSIGKeysQuery_stmt->
      execute();

    SSqlStatement::row_t row;

    while(d_getTSIGKeysQuery_stmt->hasNextRow()) {
      d_getTSIGKeysQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("get-tsig-keys-query", row, 3);
      struct TSIGKey key;
      try {
        key.name = DNSName(row[0]);
        key.algorithm = DNSName(row[1]);
      } catch (...) {
        continue;
      }
      key.key = row[2];
      keys.push_back(key);
    }

    d_getTSIGKeysQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve TSIG keys: "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::getDomainKeys(const DNSName& name, std::vector<KeyData>& keys)
{
  if(!d_dnssecQueries)
    return false;

  try {
    reconnectIfNeeded();

    d_ListDomainKeysQuery_stmt->
      bind("domain", name)->
      execute();

    SSqlStatement::row_t row;
    KeyData kd;
    while(d_ListDomainKeysQuery_stmt->hasNextRow()) {
      d_ListDomainKeysQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("list-domain-keys-query", row, 5);
      //~ for(const auto& val: row) {
        //~ cerr<<"'"<<val<<"'"<<endl;
      //~ }
      pdns::checked_stoi_into(kd.id, row[0]);
      pdns::checked_stoi_into(kd.flags, row[1]);
      kd.active = row[2] == "1";
      kd.published = row[3] == "1";
      kd.content = row[4];
      keys.push_back(kd);
    }

    d_ListDomainKeysQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list keys: "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta)
{
  try {
    reconnectIfNeeded();

    d_GetAllDomainMetadataQuery_stmt->
      bind("domain", name)->
      execute();

    SSqlStatement::row_t row;

    while(d_GetAllDomainMetadataQuery_stmt->hasNextRow()) {
      d_GetAllDomainMetadataQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("get-all-domain-metadata-query", row, 2);

      if (d_dnssecQueries || !isDnssecDomainMetadata(row[0]))
        meta[row[0]].push_back(row[1]);
    }

    d_GetAllDomainMetadataQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list metadata for domain '" + name.toLogString() + "': "+e.txtReason());
  }

  return true;
}


bool GSQLBackend::getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta)
{
  if(!d_dnssecQueries && isDnssecDomainMetadata(kind))
    return false;

  try {
    reconnectIfNeeded();

    d_GetDomainMetadataQuery_stmt->
      bind("domain", name)->
      bind("kind", kind)->
      execute();

    SSqlStatement::row_t row;

    while(d_GetDomainMetadataQuery_stmt->hasNextRow()) {
      d_GetDomainMetadataQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("get-domain-metadata-query", row, 1);
      meta.push_back(row[0]);
    }

    d_GetDomainMetadataQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to get metadata kind '" + kind + "' for domain '" + name.toLogString() + "': "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  if(!d_dnssecQueries && isDnssecDomainMetadata(kind))
    return false;

  try {
    reconnectIfNeeded();

    d_ClearDomainMetadataQuery_stmt->
      bind("domain", name)->
      bind("kind", kind)->
      execute()->
      reset();
    if(!meta.empty()) {
      for(const auto& value: meta) {
         d_SetDomainMetadataQuery_stmt->
           bind("kind", kind)->
           bind("content", value)->
           bind("domain", name)->
           execute()->
           reset();
      }
    }
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to set metadata kind '" + kind + "' for domain '" + name.toLogString() + "': "+e.txtReason());
  }

  return true;
}

void GSQLBackend::lookup(const QType& qtype, const DNSName& qname, int domain_id, DNSPacket* /* pkt_p */)
{
  try {
    reconnectIfNeeded();

    if(qtype.getCode()!=QType::ANY) {
      if(domain_id < 0) {
        d_query_name = "basic-query";
        d_query_stmt = &d_NoIdQuery_stmt;
        (*d_query_stmt)->
          bind("qtype", qtype.toString())->
          bind("qname", qname);
      } else {
        d_query_name = "id-query";
        d_query_stmt = &d_IdQuery_stmt;
        (*d_query_stmt)->
          bind("qtype", qtype.toString())->
          bind("qname", qname)->
          bind("domain_id", domain_id);
      }
    } else {
      // qtype==ANY
      if(domain_id < 0) {
        d_query_name = "any-query";
        d_query_stmt = &d_ANYNoIdQuery_stmt;
        (*d_query_stmt)->
          bind("qname", qname);
      } else {
        d_query_name = "any-id-query";
        d_query_stmt = &d_ANYIdQuery_stmt;
        (*d_query_stmt)->
          bind("qname", qname)->
          bind("domain_id", domain_id);
      }
    }

    (*d_query_stmt)->
      execute();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to lookup '" + qname.toLogString() + "|" + qtype.toString() + "':"+e.txtReason());
  }

  d_list=false;
  d_qname=qname;
}

bool GSQLBackend::list(const DNSName &target, int domain_id, bool include_disabled)
{
  DLOG(g_log<<"GSQLBackend constructing handle for list of domain id '"<<domain_id<<"'"<<endl);

  try {
    reconnectIfNeeded();

    d_query_name = "list-query";
    d_query_stmt = &d_listQuery_stmt;
    (*d_query_stmt)->
      bind("include_disabled", (int)include_disabled)->
      bind("domain_id", domain_id)->
      execute();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list domain '" + target.toLogString() + "': "+e.txtReason());
  }

  d_list=true;
  d_qname.clear();

  return true;
}

bool GSQLBackend::listSubZone(const DNSName &zone, int domain_id) {

  string wildzone = "%." + zone.makeLowerCase().toStringNoDot();

  try {
    reconnectIfNeeded();

    d_query_name = "list-subzone-query";
    d_query_stmt = &d_listSubZoneQuery_stmt;
    (*d_query_stmt)->
      bind("zone", zone)->
      bind("wildzone", wildzone)->
      bind("domain_id", domain_id)->
      execute();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list SubZones for domain '" + zone.toLogString() + "': "+e.txtReason());
  }

  d_list=false;
  d_qname.clear();

  return true;
}

bool GSQLBackend::get(DNSResourceRecord &r)
{
  // g_log << "GSQLBackend get() was called for "<<qtype.toString() << " record: ";
  SSqlStatement::row_t row;

skiprow:
  if((*d_query_stmt)->hasNextRow()) {
    try {
      (*d_query_stmt)->nextRow(row);
      if (!d_list) {
        ASSERT_ROW_COLUMNS(d_query_name, row, 8); // lookup(), listSubZone()
      }
      else {
        ASSERT_ROW_COLUMNS(d_query_name, row, 9); // list()
      }
    } catch (SSqlException &e) {
      throw PDNSException("GSQLBackend get: "+e.txtReason());
    }
    try {
      extractRecord(row, r);
    } catch (...) {
      goto skiprow;
    }
    return true;
  }

  try {
    (*d_query_stmt)->reset();
  } catch (SSqlException &e) {
      throw PDNSException("GSQLBackend get: "+e.txtReason());
  }
  d_query_stmt = nullptr;
  return false;
}

bool GSQLBackend::superMasterAdd(const AutoPrimary& primary)
{
  try{
    reconnectIfNeeded();

    d_AddSuperMaster_stmt ->
      bind("ip",primary.ip)->
      bind("nameserver",primary.nameserver)->
      bind("account",primary.account)->
      execute()->
      reset();

  }
  catch (SSqlException &e){
    throw PDNSException("GSQLBackend unable to insert an autoprimary with IP " + primary.ip + " and nameserver name '" + primary.nameserver + "' and account '" + primary.account + "': " + e.txtReason());
  }
  return true;

}

bool GSQLBackend::autoPrimaryRemove(const AutoPrimary& primary)
{
  try{
    reconnectIfNeeded();

    d_RemoveAutoPrimary_stmt ->
      bind("ip",primary.ip)->
      bind("nameserver",primary.nameserver)->
      execute()->
      reset();

  }
  catch (SSqlException &e){
    throw PDNSException("GSQLBackend unable to remove an autoprimary with IP " + primary.ip + " and nameserver name '" + primary.nameserver + "': " + e.txtReason());
  }
  return true;

}

bool GSQLBackend::autoPrimariesList(std::vector<AutoPrimary>& primaries)
{
  try{
    reconnectIfNeeded();

    d_ListAutoPrimaries_stmt->
      execute()->
      getResult(d_result)->
      reset();
  }
  catch (SSqlException &e){
     throw PDNSException("GSQLBackend unable to list autoprimaries: " + e.txtReason());
  }

  for(const auto& row : d_result) {
     ASSERT_ROW_COLUMNS("list-autoprimaries", row, 3);
     primaries.emplace_back(row[0], row[1], row[2]);
  }

  return true;
}

bool GSQLBackend::superMasterBackend(const string &ip, const DNSName &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **ddb)
{
  // check if we know the ip/ns couple in the database
  for(const auto & i : nsset) {
    try {
      reconnectIfNeeded();

      d_SuperMasterInfoQuery_stmt->
        bind("ip", ip)->
        bind("nameserver", i.content)->
        execute()->
        getResult(d_result)->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to search for a supermaster with IP " + ip + " and nameserver name '" + i.content + "' for domain '" + domain.toLogString() + "': "+e.txtReason());
    }
    if(!d_result.empty()) {
      ASSERT_ROW_COLUMNS("supermaster-query", d_result[0], 1);
      *nameserver=i.content;
      *account=d_result[0][0];
      *ddb=this;
      return true;
    }
  }
  return false;
}

bool GSQLBackend::createDomain(const DNSName& domain, const DomainInfo::DomainKind kind, const vector<ComboAddress>& masters, const string& account)
{
  vector<string> masters_s;
  masters_s.reserve(masters.size());
  for (const auto& master : masters) {
    masters_s.push_back(master.toStringWithPortExcept(53));
  }

  try {
    reconnectIfNeeded();

    // clang-format off
    d_InsertZoneQuery_stmt->
      bind("type", toUpper(DomainInfo::getKindString(kind)))->
      bind("domain", domain)->
      bind("masters", boost::join(masters_s, ", "))->
      bind("account", account)->
      execute()->
      reset();
    // clang-format on
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to insert new domain '"+domain.toLogString()+"': "+ e.txtReason());
  }
  return true;
}

bool GSQLBackend::createSlaveDomain(const string& ip, const DNSName& domain, const string& nameserver, const string& account)
{
  string name;
  vector<ComboAddress> masters({ComboAddress(ip, 53)});
  try {
    if (!nameserver.empty()) {
      // figure out all IP addresses for the master
      reconnectIfNeeded();

      d_GetSuperMasterIPs_stmt->
        bind("nameserver", nameserver)->
        bind("account", account)->
        execute()->
        getResult(d_result)->
        reset();
      if (!d_result.empty()) {
        // collect all IP addresses
        vector<ComboAddress> tmp;
        for(const auto& row: d_result) {
          if (account == row[1])
            tmp.emplace_back(row[0], 53);
        }
        // set them as domain's masters, comma separated
        masters = tmp;
      }
    }
    createDomain(domain, DomainInfo::Slave, masters, account);
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to insert new slave domain '"+domain.toLogString()+"': "+ e.txtReason());
  }
  return true;
}

bool GSQLBackend::deleteDomain(const DNSName &domain)
{
  if (!d_inTransaction) {
    throw PDNSException("deleteDomain called outside of transaction");
  }

  DomainInfo di;
  if (!getDomainInfo(domain, di)) {
    return false;
  }

  try {
    reconnectIfNeeded();

    d_DeleteZoneQuery_stmt->
      bind("domain_id", di.id)->
      execute()->
      reset();
    d_ClearDomainAllMetadataQuery_stmt->
      bind("domain", domain)->
      execute()->
      reset();
    d_ClearDomainAllKeysQuery_stmt->
      bind("domain", domain)->
      execute()->
      reset();
    d_DeleteCommentsQuery_stmt->
      bind("domain_id", di.id)->
      execute()->
      reset();
    d_DeleteDomainQuery_stmt->
      bind("domain", domain)->
      execute()->
      reset();
  }
  catch(SSqlException &e) {
    throw PDNSException("Database error trying to delete domain '"+domain.toLogString()+"': "+ e.txtReason());
  }
  return true;
}

void GSQLBackend::getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled)
{
  DLOG(g_log<<"GSQLBackend retrieving all domains."<<endl);

  try {
    reconnectIfNeeded();

    d_getAllDomainsQuery_stmt->
      bind("include_disabled", (int)include_disabled)->
      execute();

    SSqlStatement::row_t row;
    while (d_getAllDomainsQuery_stmt->hasNextRow()) {
      d_getAllDomainsQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("get-all-domains-query", row, 8);
      DomainInfo di;
      pdns::checked_stoi_into(di.id, row[0]);
      try {
        di.zone = DNSName(row[1]);
      } catch (...) {
        continue;
      }

      if (pdns_iequals(row[3], "MASTER")) {
        di.kind = DomainInfo::Master;
      } else if (pdns_iequals(row[3], "SLAVE")) {
        di.kind = DomainInfo::Slave;
      } else if (pdns_iequals(row[3], "NATIVE")) {
        di.kind = DomainInfo::Native;
      }
      else if (pdns_iequals(row[3], "PRODUCER")) {
        di.kind = DomainInfo::Producer;
      }
      else if (pdns_iequals(row[3], "CONSUMER")) {
        di.kind = DomainInfo::Consumer;
      }
      else {
        g_log<<Logger::Warning<<"Could not parse domain kind '"<<row[3]<<"' as one of 'MASTER', 'SLAVE' or 'NATIVE'. Setting zone kind to 'NATIVE'"<<endl;
        di.kind = DomainInfo::Native;
      }

      if (!row[4].empty()) {
        vector<string> masters;
        stringtok(masters, row[4], " ,\t");
        for(const auto& m : masters) {
          try {
            di.masters.emplace_back(m, 53);
          } catch(const PDNSException &e) {
            g_log<<Logger::Warning<<"Could not parse master address ("<<m<<") for zone '"<<di.zone<<"': "<<e.reason;
          }
        }
      }

      if (getSerial && !row[2].empty()) {
        SOAData sd;
        try {
          fillSOAData(row[2], sd);
          di.serial = sd.serial;
        }
        catch (...) {
          di.serial = 0;
        }
      }

      try {
        pdns::checked_stoi_into(di.notified_serial, row[5]);
        pdns::checked_stoi_into(di.last_check, row[6]);
      } catch(...) {
        continue;
      }

      di.account = row[7];

      di.backend = this;

      domains->push_back(di);
    }
    d_getAllDomainsQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("Database error trying to retrieve all domains:" + e.txtReason());
  }
}

bool GSQLBackend::replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  try {
    reconnectIfNeeded();

    if (!d_inTransaction) {
      throw PDNSException("replaceRRSet called outside of transaction");
    }

    if (qt != QType::ANY) {
      if (d_upgradeContent) {
        d_DeleteRRSetQuery_stmt->
          bind("domain_id", domain_id)->
          bind("qname", qname)->
          bind("qtype", "TYPE"+std::to_string(qt.getCode()))->
          execute()->
          reset();
      }
      d_DeleteRRSetQuery_stmt->
        bind("domain_id", domain_id)->
        bind("qname", qname)->
        bind("qtype", qt.toString())->
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
    throw PDNSException("GSQLBackend unable to delete RRSet " + qname.toLogString() + "|" + qt.toString() + ": "+e.txtReason());
  }

  if (rrset.empty()) {
    try {
      reconnectIfNeeded();

      d_DeleteCommentRRsetQuery_stmt->
        bind("domain_id", domain_id)->
        bind("qname", qname)->
        bind("qtype", qt.toString())->
        execute()->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to delete comment for RRSet " + qname.toLogString() + "|" + qt.toString() + ": "+e.txtReason());
    }
  }
  for(const auto& rr: rrset) {
    feedRecord(rr, DNSName());
  }

  return true;
}

bool GSQLBackend::feedRecord(const DNSResourceRecord& r, const DNSName& ordername, bool /* ordernameIsNSEC3 */)
{
  int prio=0;
  string content(r.content);
  if (r.qtype == QType::MX || r.qtype == QType::SRV) {
    string::size_type pos = content.find_first_not_of("0123456789");
    if (pos != string::npos) {
      pdns::checked_stoi_into(prio, content.substr(0,pos));
      boost::erase_head(content, pos);
    }
    boost::trim_left(content);
  }

  try {
    reconnectIfNeeded();

    d_InsertRecordQuery_stmt->
      bind("content",content)->
      bind("ttl",r.ttl)->
      bind("priority",prio)->
      bind("qtype",r.qtype.toString())->
      bind("domain_id",r.domain_id)->
      bind("disabled",r.disabled)->
      bind("qname",r.qname);

    if (!ordername.empty())
      d_InsertRecordQuery_stmt->bind("ordername", ordername.labelReverse().makeLowerCase().toString(" ", false));
    else
      d_InsertRecordQuery_stmt->bindNull("ordername");

    if (d_dnssecQueries)
      d_InsertRecordQuery_stmt->bind("auth", r.auth);
    else
      d_InsertRecordQuery_stmt->bind("auth", true);

    d_InsertRecordQuery_stmt->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to feed record " + r.qname.toLogString() + "|" + r.qtype.toString() + ": "+e.txtReason());
  }
  return true; // XXX FIXME this API should not return 'true' I think -ahu
}

bool GSQLBackend::feedEnts(int domain_id, map<DNSName,bool>& nonterm)
{
  for(const auto& nt: nonterm) {
    try {
      reconnectIfNeeded();

      d_InsertEmptyNonTerminalOrderQuery_stmt->
        bind("domain_id",domain_id)->
        bind("qname", nt.first)->
        bindNull("ordername")->
        bind("auth",(nt.second || !d_dnssecQueries))->
        execute()->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to feed empty non-terminal with name '" + nt.first.toLogString() + "': "+e.txtReason());
    }
  }
  return true;
}

bool GSQLBackend::feedEnts3(int domain_id, const DNSName& /* domain */, map<DNSName, bool>& nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow)
{
  if(!d_dnssecQueries)
      return false;

  string ordername;

  for(const auto& nt: nonterm) {
    try {
      reconnectIfNeeded();

      d_InsertEmptyNonTerminalOrderQuery_stmt->
        bind("domain_id",domain_id)->
        bind("qname", nt.first);
      if (narrow || !nt.second) {
        d_InsertEmptyNonTerminalOrderQuery_stmt->
          bindNull("ordername");
      } else {
        ordername=toBase32Hex(hashQNameWithSalt(ns3prc, nt.first));
        d_InsertEmptyNonTerminalOrderQuery_stmt->
          bind("ordername", ordername);
      }
      d_InsertEmptyNonTerminalOrderQuery_stmt->
        bind("auth",nt.second)->
        execute()->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("GSQLBackend unable to feed empty non-terminal with name '" + nt.first.toLogString() + "' (hashed name '"+ toBase32Hex(hashQNameWithSalt(ns3prc, nt.first)) + "') : "+e.txtReason());
    }
  }
  return true;
}

bool GSQLBackend::startTransaction(const DNSName &domain, int domain_id)
{
  try {
    reconnectIfNeeded();

    if (inTransaction()) {
      throw PDNSException("Attempted to start transaction while one was already active (domain '" + domain.toLogString() + "')");
    }
    d_db->startTransaction();
    d_inTransaction = true;
    if(domain_id >= 0) {
      d_DeleteZoneQuery_stmt->
        bind("domain_id", domain_id)->
        execute()->
        reset();
    }
  }
  catch (SSqlException &e) {
    d_inTransaction = false;
    throw PDNSException("Database failed to start transaction for domain '" + domain.toLogString() + "': "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::commitTransaction()
{
  try {
    d_db->commit();
    d_inTransaction = false;
  }
  catch (SSqlException &e) {
    d_inTransaction = false;
    throw PDNSException("Database failed to commit transaction: "+e.txtReason());
  }
  return true;
}

bool GSQLBackend::abortTransaction()
{
  try {
    d_db->rollback();
    d_inTransaction = false;
  }
  catch(SSqlException &e) {
    d_inTransaction = false;
    throw PDNSException("Database failed to abort transaction: "+string(e.txtReason()));
  }
  return true;
}

bool GSQLBackend::listComments(const uint32_t domain_id)
{
  try {
    reconnectIfNeeded();

    d_query_name = "list-comments-query";
    d_query_stmt = &d_ListCommentsQuery_stmt;
    (*d_query_stmt)->
      bind("domain_id", domain_id)->
      execute();
  }
  catch(SSqlException &e) {
    throw PDNSException("GSQLBackend unable to list comments for domain id " + std::to_string(domain_id) + ": "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::getComment(Comment& comment)
{
  SSqlStatement::row_t row;

  for(;;) {
    if (!(*d_query_stmt)->hasNextRow()) {
      try {
        (*d_query_stmt)->reset();
      } catch(SSqlException &e) {
        throw PDNSException("GSQLBackend comment get: "+e.txtReason());
      }
      d_query_stmt = nullptr;
      return false;
    }

    try {
      (*d_query_stmt)->nextRow(row);
      ASSERT_ROW_COLUMNS(d_query_name, row, 6);
    } catch(SSqlException &e) {
      throw PDNSException("GSQLBackend comment get: "+e.txtReason());
    }
    try {
      extractComment(row, comment);
    } catch (...) {
      continue;
    }
    return true;
  }
}

bool GSQLBackend::feedComment(const Comment& comment)
{
  try {
    reconnectIfNeeded();

    d_InsertCommentQuery_stmt->
      bind("domain_id",comment.domain_id)->
      bind("qname",comment.qname)->
      bind("qtype",comment.qtype.toString())->
      bind("modified_at",comment.modified_at)->
      bind("account",comment.account)->
      bind("content",comment.content)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to feed comment for RRSet '" + comment.qname.toLogString() + "|" + comment.qtype.toString() + "': "+e.txtReason());
  }

  return true;
}

bool GSQLBackend::replaceComments(const uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<Comment>& comments)
{
  try {
    reconnectIfNeeded();

    if (!d_inTransaction) {
      throw PDNSException("replaceComments called outside of transaction");
    }

    d_DeleteCommentRRsetQuery_stmt->
      bind("domain_id",domain_id)->
      bind("qname", qname)->
      bind("qtype",qt.toString())->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to delete comment for RRSet '" + qname.toLogString() + "|" + qt.toString() + "': "+e.txtReason());
  }

  for(const auto& comment: comments) {
    feedComment(comment);
  }

  return true;
}

string GSQLBackend::directBackendCmd(const string &query)
{
 try {
   ostringstream out;

   auto stmt = d_db->prepare(query,0);

   reconnectIfNeeded();

   stmt->execute();

   SSqlStatement::row_t row;

   while(stmt->hasNextRow()) {
     stmt->nextRow(row);
     for(const auto& col: row)
       out<<"\'"<<col<<"\'\t";
     out<<endl;
   }

   return out.str();
 }
 catch (SSqlException &e) {
   throw PDNSException("GSQLBackend unable to execute direct command query '" + query + "': "+e.txtReason());
 }
}

string GSQLBackend::pattern2SQLPattern(const string &pattern)
{
  string escaped_pattern = boost::replace_all_copy(pattern,"\\","\\\\");
  boost::replace_all(escaped_pattern,"_","\\_");
  boost::replace_all(escaped_pattern,"%","\\%");
  boost::replace_all(escaped_pattern,"*","%");
  boost::replace_all(escaped_pattern,"?","_");
  return escaped_pattern;
}

bool GSQLBackend::searchRecords(const string &pattern, int maxResults, vector<DNSResourceRecord>& result)
{
  d_qname.clear();
  string escaped_pattern = pattern2SQLPattern(pattern);
  try {
    reconnectIfNeeded();

    d_SearchRecordsQuery_stmt->
      bind("value", escaped_pattern)->
      bind("value2", escaped_pattern)->
      bind("limit", maxResults)->
      execute();

    while(d_SearchRecordsQuery_stmt->hasNextRow())
    {
      SSqlStatement::row_t row;
      DNSResourceRecord r;
      d_SearchRecordsQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("search-records-query", row, 8);
      try {
        extractRecord(row, r);
      } catch (...) {
        continue;
      }
      result.push_back(r);
    }

    d_SearchRecordsQuery_stmt->reset();

    return true;
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to search for records with pattern '" + pattern + "' (escaped pattern '" + escaped_pattern + "'): "+e.txtReason());
  }
}

bool GSQLBackend::searchComments(const string &pattern, int maxResults, vector<Comment>& result)
{
  Comment c;
  string escaped_pattern = pattern2SQLPattern(pattern);
  try {
    reconnectIfNeeded();

    d_SearchCommentsQuery_stmt->
      bind("value", escaped_pattern)->
      bind("value2", escaped_pattern)->
      bind("limit", maxResults)->
      execute();

    while(d_SearchCommentsQuery_stmt->hasNextRow()) {
      SSqlStatement::row_t row;
      d_SearchCommentsQuery_stmt->nextRow(row);
      ASSERT_ROW_COLUMNS("search-comments-query", row, 6);
      Comment comment;
      extractComment(row, comment);
      result.push_back(comment);
    }

    d_SearchCommentsQuery_stmt->reset();

    return true;
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to search for comments with pattern '" + pattern + "' (escaped pattern '" + escaped_pattern + "'): "+e.txtReason());
  }
}

void GSQLBackend::extractRecord(SSqlStatement::row_t& row, DNSResourceRecord& r)
{
  static const int defaultTTL = ::arg().asNum( "default-ttl" );

  if (row[1].empty())
      r.ttl = defaultTTL;
  else
      pdns::checked_stoi_into(r.ttl, row[1]);

  if(!d_qname.empty())
    r.qname=d_qname;
  else
    r.qname=DNSName(row[6]);

  r.qtype=row[3];

  if (d_upgradeContent && DNSRecordContent::isUnknownType(row[3]) && DNSRecordContent::isRegisteredType(r.qtype, r.qclass)) {
    r.content = DNSRecordContent::upgradeContent(r.qname, r.qtype, row[0]);
  }
  else if (r.qtype==QType::MX || r.qtype==QType::SRV) {
    r.content.reserve(row[2].size() + row[0].size() + 1);
    r.content=row[2]+" "+row[0];
  }
  else {
    r.content=std::move(row[0]);
  }

  r.last_modified=0;

  if(d_dnssecQueries)
    r.auth = !row[7].empty() && row[7][0]=='1';
  else
    r.auth = true;

  r.disabled = !row[5].empty() && row[5][0]=='1';

  pdns::checked_stoi_into(r.domain_id, row[4]);

  if (row.size() > 8) {   // if column 8 exists, it holds an ordername
    if (!row.at(8).empty()) {
      r.ordername=DNSName(boost::replace_all_copy(row.at(8), " ", ".")).labelReverse();
    }
    else {
      r.ordername.clear();
    }
  }
  else {
    r.ordername.clear();
  }
}

void GSQLBackend::extractComment(SSqlStatement::row_t& row, Comment& comment)
{
  pdns::checked_stoi_into(comment.domain_id, row[0]);
  comment.qname = DNSName(row[1]);
  comment.qtype = row[2];
  pdns::checked_stoi_into(comment.modified_at, row[3]);
  comment.account = std::move(row[4]);
  comment.content = std::move(row[5]);
}

SSqlStatement::~SSqlStatement() {
// make sure vtable won't break
}
