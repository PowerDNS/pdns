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
#ifndef PDNS_REC_CHANNEL
#define PDNS_REC_CHANNEL
#include <string>
#include <map>
#include <vector>
#include <inttypes.h>
#include <sys/un.h>
#include <pthread.h>
#include "iputils.hh"
#include "dnsname.hh"
#include <atomic>

/** this class is used both to send and answer channel commands to the PowerDNS Recursor */
class RecursorControlChannel
{
public:
  RecursorControlChannel();

  ~RecursorControlChannel();

  int listen(const std::string& filename);
  void connect(const std::string& path, const std::string& filename);

  uint64_t getStat(const std::string& name);

  void send(const std::string& msg, const std::string* remote=nullptr, unsigned int timeout=5);
  std::string recv(std::string* remote=0, unsigned int timeout=5);

  int d_fd;
private:
  struct sockaddr_un d_local;
};

class RecursorControlParser
{
public:
  RecursorControlParser()
  {
  }
  static void nop(void){}
  typedef void func_t(void);
  std::string getAnswer(const std::string& question, func_t** func);
};

std::map<std::string, std::string> getAllStatsMap();
extern pthread_mutex_t g_carbon_config_lock;
void sortPublicSuffixList();
std::vector<std::pair<DNSName, uint16_t> >* pleaseGetQueryRing();
std::vector<std::pair<DNSName, uint16_t> >* pleaseGetServfailQueryRing();
std::vector<std::pair<DNSName, uint16_t> >* pleaseGetBogusQueryRing();
std::vector<ComboAddress>* pleaseGetRemotes();
std::vector<ComboAddress>* pleaseGetServfailRemotes();
std::vector<ComboAddress>* pleaseGetBogusRemotes();
std::vector<ComboAddress>* pleaseGetLargeAnswerRemotes();
std::vector<ComboAddress>* pleaseGetTimeouts();
DNSName getRegisteredName(const DNSName& dom);
std::atomic<unsigned long>* getDynMetric(const std::string& str);
optional<uint64_t> getStatByName(const std::string& name);
void registerAllStats();
#endif 
