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
#include <cstdint>

#include "namespaces.hh"

struct EDNSExtendedError
{
  enum class code : uint16_t
  {
    Other = 0,
    UnsupportedDNSKEYAlgorithm = 1,
    UnsupportedDSDigestType = 2,
    StaleAnswer = 3,
    ForgedAnswer = 4,
    DNSSECIndeterminate = 5,
    DNSSECBogus = 6,
    SignatureExpired = 7,
    SignatureNotYetValid = 8,
    DNSKEYMissing = 9,
    RRSIGsMissing = 10,
    NoZoneKeyBitSet = 11,
    NSECMissing = 12,
    CachedError = 13,
    NotReady = 14,
    Blocked = 15,
    Censored = 16,
    Filtered = 17,
    Prohibited = 18,
    StaleNXDOMAINAnswer = 19,
    NotAuthoritative = 20,
    NotSupported = 21,
    NoReachableAuthority = 22,
    NetworkError = 23,
    InvalidData = 24,
    SignatureExpiredBeforeValid = 25,
    TooEarly = 26,
    UnsupportedNSEC3IterationsValue = 27,
    UnableToConformToPolicy = 28,
    Synthesized = 29,
  };
  uint16_t infoCode;
  std::string extraText;
};

bool getEDNSExtendedErrorOptFromString(const char* option, unsigned int len, EDNSExtendedError& eee);
bool getEDNSExtendedErrorOptFromString(const string& option, EDNSExtendedError& eee);
string makeEDNSExtendedErrorOptString(const EDNSExtendedError& eee);
