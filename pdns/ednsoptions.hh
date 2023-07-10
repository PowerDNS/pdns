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
#pragma once
#include "namespaces.hh"

struct EDNSOptionCode
{
  enum EDNSOptionCodeEnum {NSID=3, DAU=5, DHU=6, N3U=7, ECS=8, EXPIRE=9, COOKIE=10, TCPKEEPALIVE=11, PADDING=12, CHAIN=13, KEYTAG=14, EXTENDEDERROR=15};
};

/* extract the position (relative to the optRR pointer!) and size of a specific EDNS0 option from a pointer on the beginning rdLen of the OPT RR */
int getEDNSOption(const char* optRR, size_t len, uint16_t wantedOption, size_t* optionValuePosition, size_t* optionValueSize);

struct EDNSOptionViewValue
{
  const char* content{nullptr};
  uint16_t size{0};
};

struct EDNSOptionView
{
  std::vector<EDNSOptionViewValue> values;
};

static constexpr size_t EDNSOptionCodeSize = 2;
static constexpr size_t EDNSOptionLengthSize = 2;

using EDNSOptionViewMap = std::map<uint16_t, EDNSOptionView>;

/* extract all EDNS0 options from a pointer on the beginning rdLen of the OPT RR */
int getEDNSOptions(const char* optRR, size_t len, EDNSOptionViewMap& options);
/* extract all EDNS0 options from the content (so after rdLen) of the OPT RR */
bool getEDNSOptionsFromContent(const std::string& content, std::vector<std::pair<uint16_t, std::string>>& options);
/* parse the next EDNS option and the return the code and length. data should point to the beginning of the option code, dataLen should be maximum length of the data (minimum of remaining size in packet and remaining size in rdata) */
bool getNextEDNSOption(const char* data, size_t dataLen, uint16_t& optionCode, uint16_t& optionLen);

void generateEDNSOption(uint16_t optionCode, const std::string& payload, std::string& res);
