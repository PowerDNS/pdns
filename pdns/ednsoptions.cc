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
#include "dns.hh"
#include "ednsoptions.hh"
#include "iputils.hh"

bool getNextEDNSOption(const char* data, size_t dataLen, uint16_t& optionCode, uint16_t& optionLen)
{
  if (data == nullptr || dataLen < (sizeof(uint16_t) + sizeof(uint16_t))) {
    return false;
  }

  size_t pos = 0;
  const uint8_t* p = reinterpret_cast<const uint8_t*>(data);

  optionCode = (static_cast<uint16_t>(p[pos]) * 256) + p[pos + 1];
  pos += EDNS_OPTION_CODE_SIZE;

  optionLen = (static_cast<uint16_t>(p[pos]) * 256) + p[pos + 1];
  pos += EDNS_OPTION_LENGTH_SIZE;
  (void) pos;

  return true;
}

/* extract the position (relative to the optRR pointer!) and size of a specific EDNS0 option from a pointer on the beginning rdLen of the OPT RR */
int getEDNSOption(const char* optRR, const size_t len, uint16_t wantedOption, size_t* optionValuePosition, size_t * optionValueSize)
{
  assert(optRR != nullptr);
  assert(optionValuePosition != nullptr);
  assert(optionValueSize != nullptr);
  size_t pos = 0;
  if (len < DNS_RDLENGTH_SIZE)
    return EINVAL;

  const uint16_t rdLen = (((unsigned char) optRR[pos]) * 256) + ((unsigned char) optRR[pos+1]);
  size_t rdPos = 0;
  pos += DNS_RDLENGTH_SIZE;
  if ((pos + rdLen) > len) {
    return EINVAL;
  }

  while(len >= (pos + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE) &&
        rdLen >= (rdPos + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) {
    uint16_t optionCode;
    uint16_t optionLen;
    if (!getNextEDNSOption(optRR + pos, len-pos, optionCode, optionLen)) {
      break;
    }

    pos += EDNS_OPTION_CODE_SIZE;
    rdPos += EDNS_OPTION_CODE_SIZE;
    pos += EDNS_OPTION_LENGTH_SIZE;
    rdPos += EDNS_OPTION_LENGTH_SIZE;

    if (optionLen > (rdLen - rdPos) || optionLen > (len - pos)) {
      return EINVAL;
    }

    if (optionCode == wantedOption) {
      *optionValuePosition = pos - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE);
      *optionValueSize = optionLen + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE;
      return 0;
    }
    else {
      /* skip this option */
      pos += optionLen;
      rdPos += optionLen;
    }
  }

  return ENOENT;
}

/* extract all EDNS0 options from a pointer on the beginning rdLen of the OPT RR */
int getEDNSOptions(const char* optRR, const size_t len, EDNSOptionViewMap& options)
{
  assert(optRR != nullptr);
  size_t pos = 0;
  if (len < DNS_RDLENGTH_SIZE)
    return EINVAL;

  const uint16_t rdLen = (((unsigned char) optRR[pos]) * 256) + ((unsigned char) optRR[pos+1]);
  size_t rdPos = 0;
  pos += DNS_RDLENGTH_SIZE;
  if ((pos + rdLen) > len) {
    return EINVAL;
  }

  while(len >= (pos + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE) &&
        rdLen >= (rdPos + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) {
    const uint16_t optionCode = (((unsigned char) optRR[pos]) * 256) + ((unsigned char) optRR[pos+1]);
    pos += EDNS_OPTION_CODE_SIZE;
    rdPos += EDNS_OPTION_CODE_SIZE;
    const uint16_t optionLen = (((unsigned char) optRR[pos]) * 256) + ((unsigned char) optRR[pos+1]);
    pos += EDNS_OPTION_LENGTH_SIZE;
    rdPos += EDNS_OPTION_LENGTH_SIZE;
    if (optionLen > (rdLen - rdPos) || optionLen > (len - pos))
      return EINVAL;

    EDNSOptionViewValue value;
    value.content = optRR + pos;
    value.size = optionLen;
    options[optionCode].values.push_back(value);

    /* skip this option */
    pos += optionLen;
    rdPos += optionLen;
  }

  return 0;
}

bool getEDNSOptionsFromContent(const std::string& content, std::vector<std::pair<uint16_t, std::string>>& options)
{
  size_t pos = 0;
  uint16_t code, len;
  const size_t contentLength = content.size();

  while (pos < contentLength && (contentLength - pos) >= (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) {
    code = (static_cast<unsigned char>(content.at(pos)) * 256) + static_cast<unsigned char>(content.at(pos+1));
    pos += EDNS_OPTION_CODE_SIZE;
    len = (static_cast<unsigned char>(content.at(pos)) * 256) + static_cast<unsigned char>(content.at(pos+1));
    pos += EDNS_OPTION_LENGTH_SIZE;

    if (pos > contentLength || len > (contentLength - pos)) {
      return false;
    }

    options.emplace_back(code, std::string(&content.at(pos), len));
    pos += len;
  }

  return true;
}

void generateEDNSOption(uint16_t optionCode, const std::string& payload, std::string& res)
{
  const uint16_t ednsOptionCode = htons(optionCode);
  const uint16_t payloadLen = htons(payload.length());
  res.append((const char *) &ednsOptionCode, sizeof ednsOptionCode);
  res.append((const char *) &payloadLen, sizeof payloadLen);
  res.append(payload);
}
