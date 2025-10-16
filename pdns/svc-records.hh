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
      // https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml#dns-svcparamkeys
      /* When adding new values, you *must* update SvcParam::SvcParam(const std::string &key, const std::string &value)
       * in svc-record.cc with the new numbers
       */
      mandatory = 0,
      alpn = 1,
      no_default_alpn = 2,
      port = 3,
      ipv4hint = 4,
      ech = 5,
      ipv6hint = 6,
      dohpath = 7,
      ohttp = 8,
      tls_supported_groups = 9,  /* https://datatracker.ietf.org/doc/draft-ietf-tls-key-share-prediction/ */
    };

  //! empty Param, unusable
  SvcParam() = delete;

  //! To create a value-less SvcParam (like no-default-alpn)
  SvcParam(const SvcParamKey &key);

  //! To create a "generic" SvcParam (for keyNNNNN and ech)
  SvcParam(const SvcParamKey &key, const std::string &value);

  //! To create a multi-value SvcParam (like mandatory)
  SvcParam(const SvcParamKey &key, std::set<std::string> &&value);

  //! To create a multi-value SvcParam (like alpn)
  SvcParam(const SvcParamKey &key, std::vector<std::string> &&value);

  //! To create a multi-value SvcParam with key values (like mandatory)
  SvcParam(const SvcParamKey &key, std::set<SvcParamKey> &&value);

  //! To create an ipv{4,6}hints SvcParam
  SvcParam(const SvcParamKey &key, std::vector<ComboAddress> &&value);

  //! To create a tls-supported-groups SvcParam
  SvcParam(const SvcParamKey &key, std::vector<uint16_t> &&value);

  //! To create a port SvcParam
  SvcParam(const SvcParamKey &key, const uint16_t value);

  //! Returns the SvcParamKey based on the input
  static SvcParamKey keyFromString(const std::string &k);

  //! Returns the SvcParamKey based on the input, generic is true when the format was 'keyNNNN'
  static SvcParamKey keyFromString(const std::string &k, bool &generic);

  //! Returns the string value of the SvcParamKey
  static std::string keyToString(const SvcParamKey &k);

  bool operator< (const SvcParam &other) const;

  bool operator==(const SvcParamKey& key) const
  {
    return key == d_key;
  }

  SvcParamKey getKey() const {
    return d_key;
  }

  uint16_t getPort() const;
  const std::vector<ComboAddress>& getIPHints() const;
  const std::vector<std::string>& getALPN() const;
  const std::set<SvcParamKey>& getMandatory() const;
  const std::string& getECH() const;
  const std::string& getValue() const;
  const std::vector<uint16_t>& getTLSSupportedGroups() const;

  bool getAutoHint() const { return d_autohint; };
  void setAutoHint(const bool value) { d_autohint = value; };

  private:
    SvcParamKey d_key;
    std::string d_value; // For keyNNNNN vals

    std::vector<std::string> d_alpn; // For ALPN
    std::set<SvcParamKey> d_mandatory; // For mandatory
    std::vector<ComboAddress> d_ipHints; // For ipv{6,4}hints
    std::string d_ech; // For Encrypted Client Hello
    std::vector<uint16_t> d_tls_supported_groups; // For tls-supported-groups
    uint16_t d_port{0}; // For port

    // Set to true if we encountered an "auto" field in hints
    // Can only be true when we read SVCParams from text
    bool d_autohint{false};

    static const std::map<std::string, SvcParamKey> SvcParams;
};
