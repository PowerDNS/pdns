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

#include "namespaces.hh"
#include <optional>
#include <time.h>
#include <variant>

class RecEventTrace
{
public:
  enum EventType : uint8_t
  {
    // Don't forget to add a new entry to the table in the .cc file!
    Processing = 1,
    RecRecv = 2,
    DistPipe = 3,
    PCacheCheck = 4,
    SyncRes = 5,
    AnswerSent = 6,
    LuaGetTag = 50,
    LuaGetTagFFI = 51,
    LuaIPFilter = 52,
    LuaPreRPZ = 53,
    LuaPreResolve = 54,
    LuaPreOutQuery = 55,
    LuaPostResolve = 56,
    LuaNoData = 57,
    LuaNXDomain = 58
  };

  static const std::map<EventType, std::string> s_eventNames;

  RecEventTrace()
  {
    reset();
  }

  RecEventTrace(const RecEventTrace& old) :
    d_events(std::move(old.d_events)),
    d_base(old.d_base),
    d_status(old.d_status)
  {
    old.d_status = Invalid;
  }
  RecEventTrace(RecEventTrace&& old) :
    d_events(std::move(old.d_events)),
    d_base(old.d_base),
    d_status(old.d_status)
  {
    old.d_status = Invalid;
  }
  RecEventTrace& operator=(const RecEventTrace& old) = delete;
  RecEventTrace& operator=(RecEventTrace&& old)
  {
    d_events = std::move(old.d_events);
    d_base = old.d_base;
    d_status = old.d_status;
    old.d_status = Invalid;
    return *this;
  }

  typedef std::variant<std::nullopt_t, bool, int32_t, uint32_t, std::string> Value_t;

  static std::string toString(const EventType v)
  {
    return s_eventNames.at(v);
  }

  static std::string toString(const Value_t& v)
  {
    if (std::holds_alternative<std::nullopt_t>(v)) {
      return "";
    }
    else if (std::holds_alternative<bool>(v)) {
      return std::to_string(std::get<bool>(v));
    }
    else if (std::holds_alternative<int32_t>(v)) {
      return std::to_string(std::get<int32_t>(v));
    }
    else if (std::holds_alternative<uint32_t>(v)) {
      return std::to_string(std::get<uint32_t>(v));
    }
    else if (std::holds_alternative<std::string>(v)) {
      return std::get<std::string>(v);
    }
    return "?";
  }

  struct Entry
  {
    Entry(Value_t& v, EventType e, bool start, uint32_t ts) :
      d_value(v), d_ts(ts), d_event(e), d_start(start)
    {
    }
    Value_t d_value;
    uint64_t d_ts;
    EventType d_event;
    bool d_start;

    std::string toString() const
    {
      std::string v = RecEventTrace::toString(d_value);
      if (!v.empty()) {
        v = "," + v;
      }
      return RecEventTrace::toString(d_event) + "(" + std::to_string(d_ts) + v + (d_start ? ")" : ",done)");
    }
  };

  void setEnabled(bool flag)
  {
    assert(d_status != Invalid);
    d_status = flag ? Enabled : Disabled;
  }

  bool enabled() const
  {
    return d_status == Enabled;
  }

  void add(EventType e, Value_t v, bool start)
  {
    assert(d_status != Invalid);
    if (d_status == Disabled) {
      return;
    }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t stamp = ts.tv_nsec + ts.tv_sec * 1000000000;
    stamp -= d_base;
    d_events.emplace_back(v, e, start, stamp);
  }

  void add(EventType e)
  {
    add(e, Value_t(std::nullopt), true);
  }

  template <class T>
  void add(EventType e, T v, bool start)
  {
    add(e, Value_t(v), start);
  }

  void clear()
  {
    d_events.clear();
    reset();
  }
  void reset()
  {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    d_base = ts.tv_nsec + ts.tv_sec * 1000000000;
    d_status = Disabled;
  }

  std::string toString() const
  {
    assert(d_status != Invalid);
    if (d_status == Disabled) {
      return "Disabled\n";
    }
    std::string ret = "eventTrace [";
    bool first = true;
    for (const auto& e : d_events) {
      if (first) {
        first = false;
      }
      else {
        ret += "; ";
      }
      ret += e.toString();
    }
    ret += ']';
    return ret;
  }

private:
  std::vector<Entry> d_events;
  uint64_t d_base;
  enum Status
  {
    Disabled,
    Invalid,
    Enabled
  };
  mutable Status d_status{Disabled};
};
