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

#include "config.h"

#ifdef HAVE_DNS_OVER_HTTPS
#ifdef HAVE_LIBH2OEVLOOP

#include <ctime>
#include <memory>
#include <string>

struct CrossProtocolQuery;
struct DNSQuestion;

std::unique_ptr<CrossProtocolQuery> getDoHCrossProtocolQueryFromDQ(DNSQuestion& dq, bool isResponse);

#include "dnsdist-doh-common.hh"

struct H2ODOHFrontend : public DOHFrontend
{
public:
  void setup() override;
  void reloadCertificates() override;

  void rotateTicketsKey(time_t now) override;
  void loadTicketsKeys(const std::string& keyFile) override;
  void handleTicketsKeyRotation() override;
  std::string getNextTicketsKeyRotation() const override;
  size_t getTicketsKeysCount() override;
};

void dohThread(ClientState* clientState);

#endif /* HAVE_LIBH2OEVLOOP */
#endif /* HAVE_DNS_OVER_HTTPS  */
