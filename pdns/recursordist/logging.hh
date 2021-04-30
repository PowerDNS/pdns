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

#include <map>
#include <memory>
#include <string>
#include <sstream>
#include <boost/optional.hpp>

#include "logr.hh"
#include "dnsname.hh"
#include "iputils.hh"

namespace Logging {

  struct Entry
  {
    size_t level;                    // level at which this was logged
    boost::optional<std::string> name;   // name parts joined with '.'
    std::string message;                 // message as send to log call
    boost::optional<std::string> error;  // error if .Error() was called
    std::map<std::string, std::string> values;
  };

  template <typename T>
  struct Loggable : public Logr::Loggable
  {
    const T& _t;
    Loggable(const T& v): _t(v) {
    }
    std::string to_string() const {
      std::ostringstream oss;
      oss << _t;
      return oss.str();
    }
  };
  template <>
  std::string Loggable<DNSName>::to_string() const;
  template <>
  std::string Loggable<ComboAddress>::to_string() const;
  template <>
  std::string Loggable<std::string>::to_string() const;
//  template <>
//  Loggable<std::string>::Loggable(const std::string& v): _t(v) {}

  typedef void(*EntryLogger)(const Entry&);

  class Logger: public Logr::Logger, public std::enable_shared_from_this<Logger>
  {
  public:
    bool enabled() const override;
    void info(const std::string& msg) const override;
    void error(int err, const std::string& msg) const override;
    void error(const std::string& err, const std::string& msg) const override;

    std::shared_ptr<Logr::Logger> v(size_t level) override;
    std::shared_ptr<Logr::Logger> withValues(const std::string& key, const Logr::Loggable& value) override;
    virtual std::shared_ptr<Logr::Logger> withName(const std::string& name) override;

    static std::shared_ptr<Logger> create(EntryLogger callback);
    static std::shared_ptr<Logger> create(EntryLogger callback, const std::string& name);

    Logger(EntryLogger callback);
    Logger(EntryLogger callback, boost::optional<std::string> name);
    Logger(std::shared_ptr<Logger> parent, boost::optional<std::string> name, size_t lvl,  EntryLogger callback);
    virtual ~Logger();

    size_t getVerbosity() const;
    void setVerbosity(size_t verbosity);
  private:
    void logMessage(const std::string& msg, boost::optional<const std::string> err) const;
    std::shared_ptr<Logger> getptr();

    std::shared_ptr<Logger> _parent{nullptr};
    EntryLogger _callback;
    boost::optional<std::string> _name;
    std::map<std::string, std::string> _values;
    size_t _verbosity{0};
    size_t _level{0};
  };
}

extern std::shared_ptr<Logging::Logger> g_slog;
