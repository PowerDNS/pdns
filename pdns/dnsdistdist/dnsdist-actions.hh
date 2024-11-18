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
#include <map>
#include <optional>
#include <string>

/* so what could you do:
   drop,
   fake up nxdomain,
   provide actual answer,
   allow & and stop processing,
   continue processing,
   modify header:    (servfail|refused|notimp), set TC=1,
   send to pool */

struct DNSQuestion;
struct DNSResponse;

class DNSAction
{
public:
  enum class Action : uint8_t
  {
    Drop,
    Nxdomain,
    Refused,
    Spoof,
    Allow,
    HeaderModify,
    Pool,
    Delay,
    Truncate,
    ServFail,
    None,
    NoOp,
    NoRecurse,
    SpoofRaw,
    SpoofPacket,
    SetTag,
  };
  static Action typeFromString(const std::string& str);
  static std::string typeToString(Action action);

  virtual Action operator()(DNSQuestion*, std::string* ruleresult) const = 0;
  virtual ~DNSAction() = default;
  virtual std::string toString() const = 0;
  virtual std::map<std::string, double> getStats() const
  {
    return {{}};
  }
  virtual void reload()
  {
  }
};

class DNSResponseAction
{
public:
  enum class Action : uint8_t
  {
    Allow,
    Delay,
    Drop,
    HeaderModify,
    ServFail,
    Truncate,
    None
  };
  virtual Action operator()(DNSResponse*, std::string* ruleresult) const = 0;
  virtual ~DNSResponseAction() = default;
  virtual std::string toString() const = 0;
  virtual void reload()
  {
  }
};

#include "dnsdist-svc.hh"
#include "iputils.hh"

namespace dnsdist::actions
{
std::shared_ptr<DNSAction> getDropAction();
std::shared_ptr<DNSAction> getAllowAction();
std::shared_ptr<DNSAction> getNoneAction();
std::shared_ptr<DNSAction> getQPSAction(int limit);
std::shared_ptr<DNSAction> getDelayAction(int delay);
std::shared_ptr<DNSAction> getTeeAction(const ComboAddress& rca, const std::optional<ComboAddress>& lca, bool addECS = false, bool addProxyProtocol = false);
std::shared_ptr<DNSAction> getPoolAction(std::string pool, bool stopProcessing);
std::shared_ptr<DNSAction> getQPSPoolAction(unsigned int limit, std::string pool, bool stopProcessing);
std::shared_ptr<DNSAction> getRCodeAction(uint8_t rcode);
std::shared_ptr<DNSAction> getERCodeAction(uint8_t rcode);
std::shared_ptr<DNSAction> getSpoofSVCAction(const std::vector<SVCRecordParameters>& parameters);
std::shared_ptr<DNSAction> getTCAction();

std::shared_ptr<DNSResponseAction> getTCResponseAction();



}
