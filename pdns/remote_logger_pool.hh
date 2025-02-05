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
#include "remote_logger.hh"
#include <memory>
#include <vector>

class RemoteLoggerPool : public RemoteLoggerInterface
{
public:
  RemoteLoggerPool(std::vector<std::shared_ptr<RemoteLoggerInterface>>&& pool);
  RemoteLoggerPool(const RemoteLoggerPool&) = delete;
  RemoteLoggerPool(RemoteLoggerPool&&) = delete;
  RemoteLoggerPool& operator=(const RemoteLoggerPool&) = delete;
  RemoteLoggerPool& operator=(RemoteLoggerPool&&) = delete;
  [[nodiscard]] RemoteLoggerInterface::Result queueData(const std::string& data) override;

  [[nodiscard]] std::string address() const override
  {
    return "";
  }

  [[nodiscard]] std::string name() const override
  {
    return "";
  }

  [[nodiscard]] std::string toString() override;

  [[nodiscard]] RemoteLoggerInterface::Stats getStats() override
  {
    Stats total_stats;
    for (auto& logger : d_pool) {
      total_stats += logger->getStats();
    }
    return total_stats;
  }

private:
  std::vector<std::shared_ptr<RemoteLoggerInterface>> d_pool;
  std::vector<std::shared_ptr<RemoteLoggerInterface>>::iterator d_pool_it;
};
