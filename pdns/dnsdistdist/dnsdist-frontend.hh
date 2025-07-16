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

#include <memory>
#include <vector>

struct ClientState;
class DNSCryptContext;
class TLSFrontend;
struct DOHFrontend;
struct DOQFrontend;
struct DOH3Frontend;

namespace dnsdist
{
const std::vector<std::shared_ptr<ClientState>>& getFrontends();
std::vector<std::shared_ptr<DNSCryptContext>> getDNSCryptFrontends(bool udpOnly);
std::vector<std::shared_ptr<TLSFrontend>> getDoTFrontends();
std::vector<std::shared_ptr<DOHFrontend>> getDoHFrontends();
std::vector<std::shared_ptr<DOQFrontend>> getDoQFrontends();
std::vector<std::shared_ptr<DOH3Frontend>> getDoH3Frontends();
}
