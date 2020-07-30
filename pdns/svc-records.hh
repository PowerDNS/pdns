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
#include <set>
#include "iputils.hh"

class SvcParam {
  public:
    enum SvcParamKey: uint16_t {
      // TODO link to IANA registry
      /* When adding new values, you *must* update SvcParam::SvcParam(const std::string &key, const std::string &value)
       * in svc-record.cc with the new numbers
       */
      mandatory = 0,
      alpn = 1,
      no_default_alpn = 2,
      port = 3,
      ipv4hint = 4,
      echconfig = 5,
      ipv6hint = 6
    };

  //! empty Param, unusable
  SvcParam();

  //! To create a value-less SvcParam (like no-default-alpn)
  SvcParam(const SvcParamKey &key);

  //! To create a "generic" SvcParam (for keyNNNNN and echconfig)
  SvcParam(const SvcParamKey &key, const std::string &value);

  //! To create a multi-value SvcParam (like mandatory)
  SvcParam(const SvcParamKey &key, const std::set<std::string> &value);

  //! To create a multi-value SvcParam (like alpn)
  SvcParam(const SvcParamKey &key, const std::vector<std::string> &value);

  //! To create a multi-value SvcParam with key values (like mandatory)
  SvcParam(const SvcParamKey &key, const std::set<SvcParamKey> &value);

  //! To create and ipv{4,6}hists SvcParam
  SvcParam(const SvcParamKey &key, const std::vector<ComboAddress> &value);

  //! To create a port SvcParam
  SvcParam(const SvcParamKey &key, const uint16_t value);

  //! Returns the SvcParamKey based on the input
  static SvcParamKey keyFromString(const std::string &k);

  //! Returns the string value of the SvcParamKey
  static std::string keyToString(const SvcParamKey &k);

  bool operator< (const SvcParam &other) const;

  SvcParamKey getKey() const {
    return d_key;
  }

  uint16_t getPort() const;
  std::vector<ComboAddress> getIPHints() const;
  std::vector<std::string> getALPN() const;
  std::set<SvcParamKey> getMandatory() const;
  std::string getEchConfig() const;
  std::string getValue() const;

  private:
    SvcParamKey d_key;
    std::string d_value; // For keyNNNNN vals

    std::vector<std::string> d_alpn; // For ALPN
    std::set<SvcParamKey> d_mandatory; // For mandatory
    std::vector<ComboAddress> d_ipHints; // For ipv{6,4}hints
    std::string d_echconfig; // For echconfig
    uint16_t d_port; // For port

    static const std::map<std::string, SvcParamKey> SvcParams;
};
