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

#include "rec-tcpout.hh"

// This line from /usr/include/openssl/ssl2.h: # define CERT char
// throws dnsrecords.hh off the rails.
#undef CERT

#include "syncres.hh"
#include "dnsname.hh"
#include "rec-main.hh"

#include "cxxsettings.hh"

timeval TCPOutConnectionManager::s_maxIdleTime;
size_t TCPOutConnectionManager::s_maxQueries;
size_t TCPOutConnectionManager::s_maxIdlePerAuth;
size_t TCPOutConnectionManager::s_maxIdlePerThread;

void TCPOutConnectionManager::cleanup(const struct timeval& now)
{
  if (s_maxIdleTime.tv_sec == 0 && s_maxIdleTime.tv_usec == 0) {
    // no maximum idle time
    return;
  }

  for (auto it = d_idle_connections.begin(); it != d_idle_connections.end();) {
    timeval idle = now - it->second.d_last_used;
    if (s_maxIdleTime < idle) {
      it = d_idle_connections.erase(it);
    }
    else {
      ++it;
    }
  }
}

void TCPOutConnectionManager::store(const struct timeval& now, const endpoints_t& endpoints, Connection&& connection)
{
  ++connection.d_numqueries;
  if (s_maxQueries > 0 && connection.d_numqueries >= s_maxQueries) {
    return;
  }

  if (d_idle_connections.size() >= s_maxIdlePerThread || d_idle_connections.count(endpoints) >= s_maxIdlePerAuth) {
    cleanup(now);
  }

  if (d_idle_connections.size() >= s_maxIdlePerThread) {
    return;
  }
  if (d_idle_connections.count(endpoints) >= s_maxIdlePerAuth) {
    return;
  }

  gettimeofday(&connection.d_last_used, nullptr);
  d_idle_connections.emplace(endpoints, std::move(connection));
}

TCPOutConnectionManager::Connection TCPOutConnectionManager::get(const endpoints_t& pair)
{
  if (d_idle_connections.count(pair) > 0) {
    auto connection = d_idle_connections.extract(pair);
    return connection.mapped();
  }
  return Connection{};
}

struct OutgoingTLSConfigTable
{
  SuffixMatchTree<pdns::rust::settings::rec::OutgoingTLSConfiguration> d_suffixToConfig;
  NetmaskTree<pdns::rust::settings::rec::OutgoingTLSConfiguration> d_netmaskToConfig;
};

static LockGuarded<OutgoingTLSConfigTable> s_outgoingTLSConfigTable;

void TCPOutConnectionManager::setupOutgoingTLSConfigTables(pdns::rust::settings::rec::Recursorsettings& settings)
{
  auto& vec = settings.outgoing.tls_configurations;
  auto table = s_outgoingTLSConfigTable.lock();
  table->d_suffixToConfig = SuffixMatchTree<pdns::rust::settings::rec::OutgoingTLSConfiguration>(); // no clear?
  table->d_netmaskToConfig.clear();
  for (const auto& entry : vec) {
    for (const auto& element : entry.suffixes) {
      DNSName name = DNSName(std::string(element));
      auto copy = entry;
      table->d_suffixToConfig.add(name, std::move(copy));
    }
    for (const auto& element : entry.subnets) {
      table->d_netmaskToConfig.insert(std::string(element)).second = entry;
    }
  }
}

std::shared_ptr<TLSCtx> TCPOutConnectionManager::getTLSContext(const std::string& name, const ComboAddress& address, bool& verboseLogging, std::string& subjectName, std::string& subjectAddress, std::string& configName)
{
  TLSContextParameters tlsParams;
  tlsParams.d_provider = "openssl";
  tlsParams.d_validateCertificates = false;
  const pdns::rust::settings::rec::OutgoingTLSConfiguration* config{nullptr};

  {
    configName = "";
    auto table = s_outgoingTLSConfigTable.lock();
    if (auto* node = table->d_netmaskToConfig.lookup(address); node != nullptr) {
      config = &node->second;
    }
    else if (const auto* found = table->d_suffixToConfig.lookup(DNSName(name)); found != nullptr) {
      config = found;
    }
    if (config != nullptr) {
      configName = std::string(config->name);
      tlsParams.d_provider = std::string(config->provider);
      tlsParams.d_validateCertificates = config->validate_certificate;
      tlsParams.d_caStore = std::string(config->ca_store);
      if (!config->subject_name.empty()) {
        subjectName = std::string(config->subject_name);
      };
      if (!config->subject_address.empty()) {
        subjectAddress = std::string(config->subject_address);
      };
      verboseLogging = config->verbose_logging;
      tlsParams.d_ciphers = std::string(config->ciphers);
      tlsParams.d_ciphers13 = std::string(config->ciphers_tls_13);
    }
  }
  return ::getTLSContext(tlsParams);
}

uint64_t getCurrentIdleTCPConnections()
{
  return broadcastAccFunction<uint64_t>([] { return t_tcp_manager.getSize(); });
}
