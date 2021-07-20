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
#include "dnsdist-svc.hh"
#include "dnswriter.hh"
#include "svc-records.hh"

bool generateSVCPayload(std::vector<uint8_t>& payload, uint16_t priority, const DNSName& target, const std::set<uint16_t>& mandatoryParams, const std::vector<std::string>& alpns, bool noDefaultAlpn, std::optional<uint16_t> port, const std::string& ech, const std::vector<ComboAddress>& ipv4hints, const std::vector<ComboAddress>& ipv6hints, const std::vector<std::pair<uint16_t, std::string>>& additionalParams)
{
  // this is an _ordered_ set and the comparison operator is properly defined,
  // so the parameters will be ordered as defined in the RFC
  std::set<SvcParam> params;

  if (!mandatoryParams.empty()) {
    std::set<SvcParam::SvcParamKey> mandatoryKeys;
    for (const auto& entry : mandatoryParams) {
      mandatoryKeys.insert(static_cast<SvcParam::SvcParamKey>(entry));
    }
    params.insert({SvcParam::SvcParamKey::mandatory, std::move(mandatoryKeys)});
  }

  if (!alpns.empty()) {
    params.insert({SvcParam::SvcParamKey::alpn, std::vector<std::string>(alpns)});
  }

  if (noDefaultAlpn) {
    params.insert({SvcParam::SvcParamKey::no_default_alpn});
  }

  if (port) {
    params.insert({SvcParam::SvcParamKey::port, *port});
  }

  if (!ipv4hints.empty()) {
    params.insert({SvcParam::SvcParamKey::ipv4hint, std::vector<ComboAddress>(ipv4hints)});
  }

  if (!ech.empty()) {
    params.insert({SvcParam::SvcParamKey::ech, ech});
  }

  if (!ipv6hints.empty()) {
    params.insert({SvcParam::SvcParamKey::ipv6hint, std::vector<ComboAddress>(ipv6hints)});
  }

  for (const auto& param : additionalParams) {
    params.insert({static_cast<SvcParam::SvcParamKey>(param.first), param.second});
  }

  if (priority == 0 && params.size() != 0) {
    return false;
  }

  payload.clear();
  /* we will remove the header, question and record header parts later */
  DNSPacketWriter pw(payload, g_rootdnsname, QType::A, QClass::IN, 0);
  pw.startRecord(g_rootdnsname, QType::A, 60, QClass::IN, DNSResourceRecord::ANSWER, false);
  size_t offset = pw.size();
  pw.xfr16BitInt(priority);
  pw.xfrName(target, false, true);
  pw.xfrSvcParamKeyVals(params);
  pw.commit();

  if (payload.size() <= offset) {
    return false;
  }

  payload.erase(payload.begin(), payload.begin() + offset);
  return true;
}

bool generateSVCPayload(std::vector<uint8_t>& payload, const SVCRecordParameters& parameters)
{
  return generateSVCPayload(payload, parameters.priority, parameters.target, parameters.mandatoryParams, parameters.alpns, parameters.noDefaultAlpn, parameters.port, parameters.ech, parameters.ipv4hints, parameters.ipv6hints, parameters.additionalParams);
}
