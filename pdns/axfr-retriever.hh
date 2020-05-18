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
#include <boost/utility.hpp>

#include "iputils.hh"
#include "dnsname.hh"
#include "resolver.hh"

class AXFRRetriever : public boost::noncopyable
{
  public:
    AXFRRetriever(const ComboAddress& remote,
                  const DNSName& zone,
                  const TSIGTriplet& tt = TSIGTriplet(),
                  const ComboAddress* laddr = NULL,
                  size_t maxReceivedBytes=0,
                  uint16_t timeout=10);
    ~AXFRRetriever();
    int getChunk(Resolver::res_t &res, vector<DNSRecord>* records=0, uint16_t timeout=10);

  private:
    void connect(uint16_t timeout);
    int getLength(uint16_t timeout);
    void timeoutReadn(uint16_t bytes, uint16_t timeoutsec=10);

    shared_array<char> d_buf;
    string d_domain;
    int d_sock;
    int d_soacount;
    ComboAddress d_remote;
    TSIGTCPVerifier d_tsigVerifier;

    size_t d_receivedBytes;
    size_t d_maxReceivedBytes;
    TSIGRecordContent d_trc;
};
