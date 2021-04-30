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
#include <memory>

// Minimal logging API based on https://github.com/go-logr/logr

namespace Logr {
  struct Loggable {
    virtual std::string to_string() const = 0;
  };

  class Logger {
  public:
    // Enabled tests whether this Logger is enabled.  For example, commandline
    // flags might be used to set the logging verbosity and disable some info
    // logs.
    virtual bool enabled() const = 0;

    // Info logs a non-error message with the given key/value pairs as context.
    //
    // The msg argument should be used to add some constant description to
    // the log line.  The key/value pairs can then be used to add additional
    // variable information.  The key/value pairs should alternate string
    // keys and arbitrary values.
    virtual void info(const std::string& msg) const = 0;

    // Error logs an error, with the given message and key/value pairs as context.
    // It functions similarly to calling Info with the "error" named value, but may
    // have unique behavior, and should be preferred for logging errors (see the
    // package documentations for more information).
    //
    // The msg field should be used to add context to any underlying error,
    // while the err field should be used to attach the actual error that
    // triggered this log line, if present.
    virtual void error(const std::string& err, const std::string& msg) const = 0;
    virtual void error(int err, const std::string& msg) const = 0;

    // V returns an Logger value for a specific verbosity level, relative to
    // this Logger.  In other words, V values are additive.  V higher verbosity
    // level means a log message is less important.  It's illegal to pass a log
    // level less than zero.
    virtual std::shared_ptr<Logger> v(size_t level) = 0;

    // WithValues adds some key-value pairs of context to a logger.
    // See Info for documentation on how key/value pairs work.
    virtual std::shared_ptr<Logger> withValues(const std::string& key, const Loggable& value) = 0;

    // WithName adds a new element to the logger's name.
    // Successive calls with WithName continue to append
    // suffixes to the logger's name.  It's strongly recommended
    // that name segments contain only letters, digits, and hyphens
    // (see the package documentation for more information).
    virtual std::shared_ptr<Logger> withName(const std::string& name) = 0;
  };
}
