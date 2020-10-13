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

// root label (1), type (2), class (2), ttl (4) + rdlen (2)
static const size_t optRecordMinimumSize = 11;

extern size_t g_EdnsUDPPayloadSize;
extern uint16_t g_PayloadSizeSelfGenAnswers;

int rewriteResponseWithoutEDNS(const std::vector<uint8_t>& initialPacket, vector<uint8_t>& newContent);
int locateEDNSOptRR(const std::vector<uint8_t> & packet, uint16_t * optStart, size_t * optLen, bool * last);
bool generateOptRR(const std::string& optRData, std::vector<uint8_t>& res, size_t maximumSize, uint16_t udpPayloadSize, uint8_t ednsrcode, bool dnssecOK);
void generateECSOption(const ComboAddress& source, string& res, uint16_t ECSPrefixLength);
int removeEDNSOptionFromOPT(char* optStart, size_t* optLen, const uint16_t optionCodeToRemove);
int rewriteResponseWithoutEDNSOption(const std::vector<uint8_t>& initialPacket, const uint16_t optionCodeToSkip, vector<uint8_t>& newContent);
int getEDNSOptionsStart(const std::vector<uint8_t>& packet, const size_t offset, uint16_t* optRDPosition, size_t * remaining);
bool isEDNSOptionInOpt(const std::vector<uint8_t>& packet, const size_t optStart, const size_t optLen, const uint16_t optionCodeToFind, size_t* optContentStart = nullptr, uint16_t* optContentLen = nullptr);
bool addEDNS(std::vector<uint8_t>& packet, size_t maximumSize, bool dnssecOK, uint16_t payloadSize, uint8_t ednsrcode);
bool addEDNSToQueryTurnedResponse(DNSQuestion& dq);
bool setNegativeAndAdditionalSOA(DNSQuestion& dq, bool nxd, const DNSName& zone, uint32_t ttl, const DNSName& mname, const DNSName& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum);

bool handleEDNSClientSubnet(DNSQuestion& dq, bool& ednsAdded, bool& ecsAdded);
bool handleEDNSClientSubnet(std::vector<uint8_t>& packet, size_t maximumSize, size_t qnameWireLength, bool& ednsAdded, bool& ecsAdded, bool overrideExisting, const string& newECSOption);

bool parseEDNSOptions(const DNSQuestion& dq);

int getEDNSZ(const DNSQuestion& dq);
bool queryHasEDNS(const DNSQuestion& dq);
bool getEDNS0Record(const DNSQuestion& dq, EDNS0Record& edns0);
