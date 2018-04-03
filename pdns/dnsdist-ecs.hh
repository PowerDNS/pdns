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

enum class ECSOverrideMethod {
  keep              = 0,
  useClientAddr     = 1,
  remove            = 2,
};
namespace std {
  string to_string(ECSOverrideMethod value);
}

int rewriteResponseWithoutEDNS(const char * packet, size_t len, vector<uint8_t>& newContent);
int locateEDNSOptRR(char * packet, size_t len, char ** optStart, size_t * optLen, bool * last);
bool handleEDNSClientSubnet(char * packet, size_t packetSize, unsigned int consumed, uint16_t * len, bool* ednsAdded, bool* ecsAdded, const ComboAddress& remote, ECSOverrideMethod overrideExisting, uint16_t ecsPrefixLength);
void generateOptRR(const std::string& optRData, string& res);
int removeEDNSOptionFromOPT(char* optStart, size_t* optLen, const uint16_t optionCodeToRemove);
int rewriteResponseWithoutEDNSOption(const char * packet, const size_t len, const uint16_t optionCodeToSkip, vector<uint8_t>& newContent);
