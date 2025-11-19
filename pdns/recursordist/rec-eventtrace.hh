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

#include "misc.hh"
#include "noinitvector.hh"

#include <optional>
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
    PacketParse = 121,
    ProcessUDP = 122,
    ProcessTCP = 123,
  };

  static const std::unordered_map<EventType, std::string> s_eventNames;

  RecEventTrace()
  {
    reset();
  }

  RecEventTrace(const RecEventTrace& old) :
    d_events(old.d_events),
    d_base(old.d_base),
    d_status(old.d_status),
    d_OTTrace(old.d_OTTrace)
  {
    // An RecEventTrace object can be copied, but the original will be marked invalid.
    // This is do detect (very likely) unintended modifications to the original after
    // the ownership changed.
    old.d_status = Invalid;
  }

  RecEventTrace(RecEventTrace&& old) noexcept :
    d_events(std::move(old.d_events)),
    d_base(old.d_base),
    d_status(old.d_status),
    d_OTTrace(old.d_OTTrace)
  {
    // An RecEventTrace object can be moved, but the original will be marked invalid.
    // This is do detect (very likely) unintended modifications to the original after
    // the ownership changed.
    old.d_status = Invalid;
  }

  RecEventTrace& operator=(const RecEventTrace& old) = delete;
  RecEventTrace& operator=(RecEventTrace&& old) noexcept
  {
    d_events = std::move(old.d_events);
    d_base = old.d_base;
    d_status = old.d_status;
    d_OTTrace = old.d_OTTrace;
    old.d_status = Invalid;
    return *this;
  }

  ~RecEventTrace() = default;

  // We distinguish between strings and byte arrays. Does not matter in C++, but in Go, Java etc it does
  using Value_t = std::variant<std::nullopt_t, bool, int64_t, std::string, PacketBuffer>;

  static std::string toString(const EventType eventType)
  {
    return s_eventNames.at(eventType);
  }

  static std::string toString(const Value_t& value)
  {
    if (std::holds_alternative<std::nullopt_t>(value)) {
      return "";
    }
    if (std::holds_alternative<bool>(value)) {
      return std::to_string(std::get<bool>(value));
    }
    if (std::holds_alternative<int64_t>(value)) {
      return std::to_string(std::get<int64_t>(value));
    }
    if (std::holds_alternative<std::string>(value)) {
      return std::get<std::string>(value);
    }
    if (std::holds_alternative<PacketBuffer>(value)) {
      const auto& packet = std::get<PacketBuffer>(value);
      return makeHexDump(std::string(reinterpret_cast<const char*>(packet.data()), packet.size())); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }
    return "?";
  }

  struct Entry
  {
    Entry(Value_t&& value, EventType eventType, bool start, int64_t timestamp, size_t parent, size_t match) :
      d_value(std::move(value)), d_ts(timestamp), d_parent(parent), d_matching(match), d_event(eventType), d_start(start)
    {
    }
    Entry(Value_t&& value, std::string custom, bool start, int64_t timestamp, size_t parent, size_t match) :
      d_value(std::move(value)), d_custom(std::move(custom)), d_ts(timestamp), d_parent(parent), d_matching(match), d_event(CustomEvent), d_start(start)
    {
    }
    Value_t d_value;
    std::vector<std::pair<string, Value_t>> d_extraValues;
    std::string d_custom;
    std::string d_valueName{"arg"};
    int64_t d_ts;
    size_t d_parent;
    size_t d_matching;
    EventType d_event;
    bool d_start;

    [[nodiscard]] std::string toString() const
    {
      std::string value = RecEventTrace::toString(d_value);
      if (!value.empty()) {
        value = "," + value;
      }
      std::string name = RecEventTrace::toString(d_event);
      if (d_event == EventType::CustomEvent) {
        name += ":" + d_custom;
      }

      return name + "(" + std::to_string(d_ts) + value + (d_start ? ")" : ",done)");
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
  size_t add(E event, Value_t&& value, bool start, size_t match, int64_t stamp = 0)
  {
    assert(d_status != Invalid);
    if (d_status == Disabled) {
      return 0;
    }

    if (stamp == 0) {
      struct timespec theTime{};
      clock_gettime(CLOCK_MONOTONIC, &theTime);
      stamp = theTime.tv_nsec + theTime.tv_sec * 1000000000;
    }
    if (stamp < d_base) {
      // If we get a ts before d_base, we adjust d_base and the existing events
      // This is possble if we add a kernel provided packet timestamp in the future
      // (Though it seems those timestamps do not use CLOCK_MONOTONIC...)
      const int64_t adj = d_base - stamp;
      for (auto& iter : d_events) {
        iter.d_ts += adj;
      }
      // and move to the new base
      d_base = stamp;
    }
    stamp -= d_base;
    d_events.emplace_back(std::move(value), event, start, stamp, d_parent, match);
    return d_events.size() - 1;
  }

  template <class E>
  size_t add(E eventType)
  {
    return add(eventType, Value_t(std::nullopt), true, 0, 0);
  }

  // We store uint32 in an int64_t
  template <class E>
  size_t add(E eventType, uint32_t value, bool start, size_t match)
  {
    return add(eventType, static_cast<int64_t>(value), start, match, 0);
  }
  // We store int32 in an int64_t
  template <class E>
  size_t add(E eventType, int32_t value, bool start, size_t match)
  {
    return add(eventType, static_cast<int64_t>(value), start, match, 0);
  }

  template <class E, class T>
  size_t add(E eventType, T value, bool start, size_t match)
  {
    return add(eventType, Value_t(value), start, match, 0);
  }

  void setValueName(size_t index, const std::string& name)
  {
    assert(d_status != Invalid);
    if (d_status == Disabled) {
      return;
    }
    d_events.at(index).d_valueName = name;
  }

  void addExtraValues(size_t index, std::vector<std::pair<std::string, Value_t>>&& values)
  {
    assert(d_status != Invalid);
    if (d_status == Disabled) {
      return;
    }
    d_events.at(index).d_extraValues = std::move(values);
  }

  void clear()
  {
    d_events.clear();
    reset();
  }

  void reset()
  {
    struct timespec theTime{};
    clock_gettime(CLOCK_MONOTONIC, &theTime);
    d_base = theTime.tv_nsec + theTime.tv_sec * 1000000000;
    d_OTTrace = false;
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
    for (const auto& event : d_events) {
      if (first) {
        first = false;
      }
      else {
        ret += "; ";
      }
      ret += event.toString();
    }
    ret += ']';
    return ret;
  }

  const std::vector<Entry>& getEvents() const
  {
    return d_events;
  }

  std::vector<pdns::trace::Span> convertToOT(const pdns::trace::InitialSpanInfo& span) const;

  size_t setParent(size_t parent)
  {
    size_t old = d_parent;
    d_parent = parent;
    return old;
  }

  bool getThisOTTraceEnabled() const
  {
    return d_OTTrace;
  }

  void setThisOTTraceEnabled()
  {
    d_OTTrace = true;
  }

  // The EventScope class is used to close (add an end event) automatically upon the scope object
  // going out of scope. It is also possible to manually close it, specifying a value to be registered
  // at the close event. In that case the dt call will become a no-op.
  class EventScope
  {
  public:
    EventScope(size_t oldParent, RecEventTrace& eventTrace) :
      d_eventTrace(eventTrace),
      d_oldParent(oldParent)
    {
      if (d_eventTrace.enabled() && !d_eventTrace.d_events.empty()) {
        d_event = d_eventTrace.d_events.back().d_event;
        d_match = d_eventTrace.d_events.size() - 1;
      }
    }

    // Only int64_t for now needed, might become a template in the future.
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
      // If the dt is called after an explicit close(), value does not matter.
      // Otherwise, it signals an implicit close, e.g. an exception was thrown
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
  int64_t d_base{0};
  size_t d_parent{0};
  enum Status : uint8_t
  {
    Disabled,
    Invalid,
    Enabled
  };
  mutable Status d_status{Disabled};
  bool d_OTTrace{false};
};
