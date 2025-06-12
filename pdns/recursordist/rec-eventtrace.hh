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
#include "misc.hh"
#include "noinitvector.hh"

#include <optional>
#include <time.h>
#include <unordered_map>
#include <variant>
#include "protozero-trace.hh"

class RecEventTrace
{
public:
  enum EventType : uint8_t
  {
    // Keep in-syc with dnsmessagge.proto!
    // Don't forget to add a new entry to the table in the .cc file!
    // Generic events
    CustomEvent = 0,
    ReqRecv = 1,
    PCacheCheck = 2,
    AnswerSent = 3,

    // Recursor specific events
    SyncRes = 100,
    LuaGetTag = 101,
    LuaGetTagFFI = 102,
    LuaIPFilter = 103,
    LuaPreRPZ = 104,
    LuaPreResolve = 105,
    LuaPreOutQuery = 106,
    LuaPostResolve = 107,
    LuaNoData = 108,
    LuaNXDomain = 109,
    LuaPostResolveFFI = 110,

    AuthRequest = 120,
  };

  static const std::unordered_map<EventType, std::string> s_eventNames;

  RecEventTrace()
  {
    reset();
  }

  RecEventTrace(const RecEventTrace& old) :
    d_events(old.d_events),
    d_base(old.d_base),
    d_status(old.d_status)
  {
    // An RecEventTrace object can be copied, but the original will be marked invalid.
    // This is do detect (very likely) unintended modifications to the original after
    // the ownership changed.
    old.d_status = Invalid;
  }

  RecEventTrace(RecEventTrace&& old) :
    d_events(std::move(old.d_events)),
    d_base(old.d_base),
    d_status(old.d_status)
  {
    // An RecEventTrace object can be moved, but the original will be marked invalid.
    // This is do detect (very likely) unintended modifications to the original after
    // the ownership changed.
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

  // We distinguish between strings and byte arrays. Does not matter in C++, but in Go, Java etc it does
  typedef std::variant<std::nullopt_t, bool, int64_t, std::string, PacketBuffer> Value_t;

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
    else if (std::holds_alternative<int64_t>(v)) {
      return std::to_string(std::get<int64_t>(v));
    }
    else if (std::holds_alternative<std::string>(v)) {
      return std::get<std::string>(v);
    }
    else if (std::holds_alternative<PacketBuffer>(v)) {
      const PacketBuffer& p = std::get<PacketBuffer>(v);
      return makeHexDump(std::string(reinterpret_cast<const char*>(p.data()), p.size()));
    }
    return "?";
  }

  struct Entry
  {
    Entry(Value_t&& v, EventType e, bool start, int64_t ts, size_t parent, size_t match) :
      d_value(std::move(v)), d_ts(ts), d_parent(parent), d_matching(match), d_event(e), d_start(start)
    {
    }
    Entry(Value_t&& v, const std::string& custom, bool start, int64_t ts, size_t parent, size_t match) :
      d_value(std::move(v)), d_custom(custom), d_ts(ts), d_parent(parent), d_matching(match), d_event(CustomEvent), d_start(start)
    {
    }
    Value_t d_value;
    std::string d_custom;
    int64_t d_ts;
    size_t d_parent;
    size_t d_matching;
    EventType d_event;
    bool d_start;

    std::string toString() const
    {
      std::string v = RecEventTrace::toString(d_value);
      if (!v.empty()) {
        v = "," + v;
      }
      std::string name = RecEventTrace::toString(d_event);
      if (d_event == EventType::CustomEvent) {
        name += ":" + d_custom;
      }

      return name + "(" + std::to_string(d_ts) + v + (d_start ? ")" : ",done)");
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

  template <class E>
  size_t add(E e, Value_t&& v, bool start, size_t match, int64_t stamp = 0)
  {
    assert(d_status != Invalid);
    if (d_status == Disabled) {
      return 0;
    }

    if (stamp == 0) {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      stamp = ts.tv_nsec + ts.tv_sec * 1000000000;
    }
    if (stamp < d_base) {
      // If we get a ts before d_base, we adjust d_base and the existing events
      // This is possble if we add a kernel provided packet timestamp in the future
      // (Though it seems those timestamps do not use CLOCK_MONOTONIC...)
      const int64_t adj = d_base - stamp;
      for (auto& i : d_events) {
        i.d_ts += adj;
      }
      // and move to the new base
      d_base = stamp;
    }
    stamp -= d_base;
    d_events.emplace_back(std::move(v), e, start, stamp, d_parent, match);
    return d_events.size() - 1;
  }

  template <class E>
  size_t add(E e)
  {
    return add(e, Value_t(std::nullopt), true, 0, 0);
  }

  // We store uint32 in an int64_t
  template <class E>
  size_t add(E e, uint32_t v, bool start, size_t match)
  {
    return add(e, static_cast<int64_t>(v), start, match, 0);
  }
  // We store int32 in an int64_t
  template <class E>
  size_t add(E e, int32_t v, bool start, size_t match)
  {
    return add(e, static_cast<int64_t>(v), start, match, 0);
  }

  template <class E, class T>
  size_t add(E e, T v, bool start, size_t match)
  {
    return add(e, Value_t(v), start, match, 0);
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

  const std::vector<Entry>& getEvents() const
  {
    return d_events;
  }

  std::vector<pdns::trace::Span> convertToOT(const pdns::trace::Span& span) const;

  size_t setParent(size_t parent)
  {
    size_t old = d_parent;
    d_parent = parent;
    return old;
  }

  class EventScope
  {
  public:
    EventScope(size_t oldParent, RecEventTrace& eventTrace) :
      d_eventTrace(eventTrace),
      d_oldParent(oldParent)
    {
      if (d_eventTrace.enabled()) {
        d_event = d_eventTrace.d_events.back().d_event;
        d_match = d_eventTrace.d_events.size() - 1;
      }
    }

    void close(int64_t val)
    {
      if (!d_eventTrace.enabled() || d_closed) {
        return;
      }
      d_eventTrace.setParent(d_oldParent);
      d_eventTrace.add(d_event, val, false, d_match);
      d_closed = true;
    }

    ~EventScope()
    {
      close(-1);
    }
    EventScope(const EventScope&) = delete;
    EventScope(EventScope&&) = delete;
    EventScope& operator=(const EventScope&) = delete;
    EventScope& operator=(EventScope&&) = delete;

  private:
    RecEventTrace& d_eventTrace;
    size_t d_oldParent;
    size_t d_match{0};
    EventType d_event{EventType::CustomEvent};
    bool d_closed{false};
  };

private:
  std::vector<Entry> d_events;
  int64_t d_base;
  size_t d_parent{0};
  enum Status : uint8_t
  {
    Disabled,
    Invalid,
    Enabled
  };
  mutable Status d_status{Disabled};
};
