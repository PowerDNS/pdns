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

#include <string>

#include "iputils.hh"
#include "noinitvector.hh"

struct DNSQuestion;

// root label (1), type (2), class (2), ttl (4) + rdlen (2)
static const size_t optRecordMinimumSize = 11;

extern size_t g_EdnsUDPPayloadSize;
extern uint16_t g_PayloadSizeSelfGenAnswers;

int rewriteResponseWithoutEDNS(const PacketBuffer& initialPacket, PacketBuffer& newContent);
bool slowRewriteEDNSOptionInQueryWithRecords(const PacketBuffer& initialPacket, PacketBuffer& newContent, bool& ednsAdded, uint16_t optionToReplace, bool& optionAdded, bool overrideExisting, const string& newOptionContent);
int locateEDNSOptRR(const PacketBuffer & packet, uint16_t * optStart, size_t * optLen, bool * last);
bool generateOptRR(const std::string& optRData, PacketBuffer& res, size_t maximumSize, uint16_t udpPayloadSize, uint8_t ednsrcode, bool dnssecOK);
void generateECSOption(const ComboAddress& source, string& res, uint16_t ECSPrefixLength);
int removeEDNSOptionFromOPT(char* optStart, size_t* optLen, const uint16_t optionCodeToRemove);
int rewriteResponseWithoutEDNSOption(const PacketBuffer& initialPacket, const uint16_t optionCodeToSkip, PacketBuffer& newContent);
int getEDNSOptionsStart(const PacketBuffer& packet, const size_t offset, uint16_t* optRDPosition, size_t * remaining);
bool isEDNSOptionInOpt(const PacketBuffer& packet, const size_t optStart, const size_t optLen, const uint16_t optionCodeToFind, size_t* optContentStart = nullptr, uint16_t* optContentLen = nullptr);
bool addEDNS(PacketBuffer& packet, size_t maximumSize, bool dnssecOK, uint16_t payloadSize, uint8_t ednsrcode);
bool addEDNSToQueryTurnedResponse(DNSQuestion& dq);
bool setNegativeAndAdditionalSOA(DNSQuestion& dq, bool nxd, const DNSName& zone, uint32_t ttl, const DNSName& mname, const DNSName& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum, bool soaInAuthoritySection);

bool handleEDNSClientSubnet(DNSQuestion& dq, bool& ednsAdded, bool& ecsAdded);
bool handleEDNSClientSubnet(PacketBuffer& packet, size_t maximumSize, size_t qnameWireLength, bool& ednsAdded, bool& ecsAdded, bool overrideExisting, const string& newECSOption);

bool parseEDNSOptions(const DNSQuestion& dq);

int getEDNSZ(const DNSQuestion& dq);
bool queryHasEDNS(const DNSQuestion& dq);
bool getEDNS0Record(const PacketBuffer& packet, EDNS0Record& edns0);

bool setEDNSOption(DNSQuestion& dq, uint16_t ednsCode, const std::string& data);

namespace dnsdist {
bool setInternalQueryRCode(InternalQueryState& state, PacketBuffer& buffer,  uint8_t rcode, bool clearAnswers);
}
