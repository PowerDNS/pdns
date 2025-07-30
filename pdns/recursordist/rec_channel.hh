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
#include <map>
#include <optional>
#include <vector>
#include <sys/un.h>
#include <pthread.h>
#include "iputils.hh"
#include "dnsname.hh"
#include "sholder.hh"
#include <atomic>

extern GlobalStateHolder<SuffixMatchNode> g_dontThrottleNames;
extern GlobalStateHolder<NetmaskGroup> g_dontThrottleNetmasks;

/** this class is used both to send and answer channel commands to the PowerDNS Recursor */
class RecursorControlChannel
{
public:
  RecursorControlChannel();

  RecursorControlChannel(const RecursorControlChannel&) = delete;
  RecursorControlChannel(RecursorControlChannel&&) = delete;
  RecursorControlChannel& operator=(const RecursorControlChannel&) = delete;
  RecursorControlChannel& operator=(RecursorControlChannel&&) = delete;
  ~RecursorControlChannel();

  int listen(const std::string& filename);
  void connect(const std::string& path, const std::string& filename);

  uint64_t getStat(const std::string& name);

  struct Answer
  {
    Answer& operator+=(const Answer& rhs)
    {
      if (d_ret == 0 && rhs.d_ret != 0) {
        d_ret = rhs.d_ret;
      }
      d_str += rhs.d_str;
      return *this;
    }
    int d_ret{0};
    std::string d_str;
  };

  static void send(int fileDesc, const Answer&, unsigned int timeout = 5, int fd_to_pass = -1);
  static RecursorControlChannel::Answer recv(int fileDesc, unsigned int timeout = 5);

  static std::atomic<bool> stop;

  [[nodiscard]] int getDescriptor() const
  {
    return d_fd;
  }

private:
  int d_fd;
  struct sockaddr_un d_local{};
};

class RecursorControlParser
{
public:
  RecursorControlParser() = default;
  static void nop() {}
  using func_t = void();

  static RecursorControlChannel::Answer getAnswer(int socket, const std::string& question, func_t** command);
};

enum class StatComponent : uint8_t
{
  API,
  Carbon,
  RecControl,
  SNMP
};

struct StatsMapEntry
{
  std::string d_prometheusName;
  std::string d_value;
};

class PrefixDashNumberCompare
{
private:
  static std::pair<std::string, std::string> prefixAndTrailingNum(const std::string& arg);

public:
  bool operator()(const std::string& lhs, const std::string& rhs) const;
};

using StatsMap = std::map<std::string, StatsMapEntry, PrefixDashNumberCompare>;

StatsMap getAllStatsMap(StatComponent component);

struct CarbonConfig
{
  std::string hostname;
  std::string instance_name;
  std::string namespace_name;
  std::vector<std::string> servers;
};

extern GlobalStateHolder<CarbonConfig> g_carbonConfig;

std::vector<std::pair<DNSName, uint16_t>>* pleaseGetQueryRing();
std::vector<std::pair<DNSName, uint16_t>>* pleaseGetServfailQueryRing();
std::vector<std::pair<DNSName, uint16_t>>* pleaseGetBogusQueryRing();
std::vector<ComboAddress>* pleaseGetRemotes();
std::vector<ComboAddress>* pleaseGetServfailRemotes();
std::vector<ComboAddress>* pleaseGetBogusRemotes();
std::vector<ComboAddress>* pleaseGetLargeAnswerRemotes();
std::vector<ComboAddress>* pleaseGetTimeouts();
DNSName getRegisteredName(const DNSName& dom);
std::atomic<unsigned long>* getDynMetric(const std::string& str, const std::string& prometheusName);
std::optional<uint64_t> getStatByName(const std::string& name);
bool isStatDisabled(StatComponent component, const std::string& name);
void disableStat(StatComponent component, const string& name);
void disableStats(StatComponent component, const string& stats);

void registerAllStats();

void doExitNicely();
RecursorControlChannel::Answer doQueueReloadLuaScript(vector<string>::const_iterator begin, vector<string>::const_iterator end);
RecursorControlChannel::Answer luaconfig(bool broadcast);
