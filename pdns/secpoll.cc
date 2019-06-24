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

#include <string>
#include <vector>
#include "dnsrecords.hh"
#include "pdnsexception.hh"
#include "misc.hh"

bool isReleaseVersion(const std::string &version) {
  return std::count(version.begin(), version.end(), '.') == 2;
}

void setSecPollToUnknownOnOK(int &secPollStatus) {
  if(secPollStatus == 1) // it was ok, now it is unknown
    secPollStatus = 0;
}

void processSecPoll(const int res, const std::vector<DNSRecord> &ret, int &secPollStatus, std::string &secPollMessage) {
  secPollMessage.clear();
  if (res != 0) { // not NOERROR
    setSecPollToUnknownOnOK(secPollStatus);
    throw PDNSException("RCODE was not NOERROR but " + RCode::to_s(res));
  }

  if (ret.empty()) { // empty NOERROR... wat?
    if(secPollStatus == 1) // it was ok, now it is unknown
      secPollStatus = 0;
    throw PDNSException("Had empty answer on NOERROR RCODE");
  }

  DNSRecord record;
  for (auto const &r: ret) {
    if (r.d_type == QType::TXT && r.d_place == DNSResourceRecord::Place::ANSWER) {
      record = r;
      break;
    }
  }

  if (record.d_name.empty()) {
    setSecPollToUnknownOnOK(secPollStatus);
    throw PDNSException("No TXT record found in response");
  }

  auto recordContent = getRR<TXTRecordContent>(record);
  if (recordContent == nullptr) {
    setSecPollToUnknownOnOK(secPollStatus);
    throw PDNSException("Could not parse TXT record content");
  }
  string content = recordContent->d_text;

  pair<string, string> split = splitField(unquotify(content), ' ');

  try {
    secPollStatus = std::stoi(split.first);
  } catch (const std::exception &e) {
    setSecPollToUnknownOnOK(secPollStatus);
    throw PDNSException(std::string("Could not parse status number: ") + e.what());
  }
  secPollMessage = split.second;
}
