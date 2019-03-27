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

#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-extended-error.hh"
#include "ednsoptions.hh"

static std::string generateExtendedError(const DNSQuestion& dq)
{
  std::string errbuf;
  const EDNSExtendedError& exerr = *(dq.ednsExtendedError);

  errbuf.reserve(4 + exerr.extra_text.length());
  if (exerr.retry) {
    errbuf.append("\x80\x00", 2);
  } else {
    errbuf.append("\x00\x00", 2);
  }
  char code[2] = { char((dq.dh->rcode << 4) | ((exerr.info_code >> 8) & 0xf)),
                   char(exerr.info_code & 0xFF) };
  errbuf.append(code, 2);
  errbuf.append(exerr.extra_text);

  return errbuf;
}

bool addEDNSExtendedError(DNSQuestion& dq)
{
  char* packet = reinterpret_cast<char*>(dq.dh);

  uint16_t optRDPosition;
  size_t remaining;
  int res = getEDNSOptionsStart(packet, dq.consumed, dq.len, &optRDPosition, &remaining);

  // If we don't have an OPT RR, then we won't add extended error information.
  //
  // We also have the same restrictions as ECS (where the function is defined),
  // which means it returns the OPT record for questions without any RR
  // except for the OPT records.
  if (res != 0) {
    return true;
  }

  std::string errbuf = generateExtendedError(dq);

  // Make sure that we have enough room in our buffer for our extended error information.
  if (dq.size < (dq.len + 4 + errbuf.length())) {
    return false;
  }

  // Make sure we actually have length in our OPT record.
  if (remaining < 2) {
    return false;
  }

  // Get our OPT record and its length.
  char *opt = packet + optRDPosition;
  unsigned int optLen = (opt[0] << 8) + opt[1];

  // Figure out the new length of the OPT record.
  unsigned int newOptLen = optLen + 4 + errbuf.length();
  if (newOptLen > 65535) {
    return false;
  }

  // Update our OPT length.
  opt[0] = (newOptLen >> 8) & 0xFF;
  opt[1] = newOptLen & 0xFF;

  // Add our new OPT RR.
  opt[optLen] = (EDNSOptionCode::EXTENDED_ERROR >> 8) & 0xFF;
  opt[optLen+1] = EDNSOptionCode::EXTENDED_ERROR & 0xFF;
  opt[optLen+2] = (errbuf.length() >> 8) & 0xFF;
  opt[optLen+3] = errbuf.length() & 0xFF;
  memcpy(opt + optLen + 4, errbuf.c_str(), errbuf.length());

  // Update the length of our packet.
  dq.len += 4 + errbuf.length();

  // And it worked!
  return true;
}

