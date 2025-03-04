/**
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

#include "logging.hh"
#include <string>
#include <mutex>
#include "utility.hh"

namespace Logging
{

std::shared_ptr<const Logger> Logger::getptr() const
{
  return shared_from_this();
}

bool Logger::enabled(Logr::Priority prio) const
{
  return _level <= _verbosity || prio != Logr::Absent;
}

void Logger::info(const std::string& msg) const
{
  logMessage(msg, Logr::Absent, boost::none);
}

void Logger::info(Logr::Priority prio, const std::string& msg) const
{
  logMessage(msg, prio, boost::none);
}

void Logger::logMessage(const std::string& msg, boost::optional<const std::string> err) const
{
  return logMessage(msg, Logr::Absent, std::move(err));
}

void Logger::logMessage(const std::string& msg, Logr::Priority prio, boost::optional<const std::string> err) const
{
  if (!enabled(prio)) {
    return;
  }
  Entry entry;
  entry.level = _level;
  entry.d_priority = prio;
  Utility::gettimeofday(&entry.d_timestamp);
  entry.name = _name;
  entry.message = msg;
  entry.error = std::move(err);
  auto parent = _parent;
  entry.values.insert(_values.begin(), _values.end());
  while (parent) {
    entry.values.insert(parent->_values.begin(), parent->_values.end());
    parent = parent->_parent;
  }
  _callback(entry);
}

void Logger::error(Logr::Priority prio, int err, const std::string& msg) const
{
  logMessage(msg, prio, std::string(stringerror(err)));
}

void Logger::error(Logr::Priority prio, const std::string& err, const std::string& msg) const
{
  logMessage(msg, prio, err);
}

void Logger::error(int err, const std::string& msg) const
{
  logMessage(msg, Logr::Absent, std::string(stringerror(err)));
}

void Logger::error(const std::string& err, const std::string& msg) const
{
  logMessage(msg, Logr::Absent, err);
}

std::shared_ptr<Logr::Logger> Logger::v(size_t level) const
{
  auto res = std::make_shared<Logger>(getptr(), _name, getVerbosity(), level + _level, _callback);
  return res;
}

std::shared_ptr<Logr::Logger> Logger::withValues(const std::map<std::string, std::string>& values) const
{
  auto res = std::make_shared<Logger>(getptr(), _name, getVerbosity(), _level, _callback);
  res->_values = values;
  return res;
}

std::shared_ptr<Logr::Logger> Logger::withName(const std::string& name) const
{
  std::shared_ptr<Logger> res;
  if (_name) {
    res = std::make_shared<Logger>(getptr(), _name.get() + "." + name, getVerbosity(), _level, _callback);
  }
  else {
    res = std::make_shared<Logger>(getptr(), name, getVerbosity(), _level, _callback);
  }
  res->setVerbosity(getVerbosity());
  return res;
}
std::shared_ptr<Logger> Logger::create(EntryLogger callback)
{
  return std::make_shared<Logger>(callback);
}
std::shared_ptr<Logger> Logger::create(EntryLogger callback, const std::string& name)
{
  return std::make_shared<Logger>(callback, name);
}

size_t Logger::getVerbosity() const
{
  return _verbosity;
}

void Logger::setVerbosity(size_t verbosity)
{
  _verbosity = verbosity;
}

Logger::Logger(EntryLogger callback) :
  _callback(callback)
{
}
Logger::Logger(EntryLogger callback, boost::optional<std::string> name) :
  _callback(callback), _name(std::move(name))
{
}
Logger::Logger(std::shared_ptr<const Logger> parent, boost::optional<std::string> name, size_t verbosity, size_t lvl, EntryLogger callback) :
  _parent(std::move(parent)), _callback(callback), _name(std::move(name)), _level(lvl), _verbosity(verbosity)
{
}

Logger::~Logger() = default;
};

std::shared_ptr<Logging::Logger> g_slog{nullptr};

const char* Logging::toTimestampStringMilli(const struct timeval& tval, std::array<char, 64>& buf, const std::string& format)
{
  size_t len = 0;
  if (format != "%s") {
    // strftime is not thread safe, it can access locale information
    static std::mutex mutex;
    auto lock = std::lock_guard(mutex);
    struct tm theTime // clang-format insists on formatting it like this
      {};
    len = strftime(buf.data(), buf.size(), format.c_str(), localtime_r(&tval.tv_sec, &theTime));
  }
  if (len == 0) {
    len = snprintf(buf.data(), buf.size(), "%lld", static_cast<long long>(tval.tv_sec));
  }

  snprintf(&buf.at(len), buf.size() - len, ".%03ld", static_cast<long>(tval.tv_usec) / 1000);
  return buf.data();
}
