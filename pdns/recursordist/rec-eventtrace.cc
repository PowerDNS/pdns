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
#include "rec-eventtrace.hh"

#define NameEntry(M) {M, #M}

const std::unordered_map<RecEventTrace::EventType, std::string> RecEventTrace::s_eventNames = {
  NameEntry(CustomEvent),
  NameEntry(ReqRecv),
  NameEntry(PCacheCheck),
  NameEntry(AnswerSent),
  NameEntry(SyncRes),
  NameEntry(LuaGetTag),
  NameEntry(LuaGetTagFFI),
  NameEntry(LuaIPFilter),
  NameEntry(LuaPreRPZ),
  NameEntry(LuaPreResolve),
  NameEntry(LuaPreOutQuery),
  NameEntry(LuaPostResolve),
  NameEntry(LuaNoData),
  NameEntry(LuaNXDomain),
  NameEntry(LuaPostResolveFFI)};

using namespace pdns::trace;

std::vector<pdns::trace::Span> RecEventTrace::convertToOT(const Span& span) const
{
  timespec realtime{};
  clock_gettime(CLOCK_REALTIME, &realtime);
  timespec monotime{};
  clock_gettime(CLOCK_MONOTONIC, &monotime);
  auto diff = (1000000000ULL * realtime.tv_sec) + realtime.tv_nsec - ((1000000000ULL * monotime.tv_sec) + monotime.tv_nsec);
  diff += d_base;

  std::vector<pdns::trace::Span> ret;
  ret.reserve((d_events.size() / 2) + 1);
  ret.emplace_back(span);
  std::map<EventType, size_t> pairs;
  for (const auto& event : d_events) {
    if (event.d_start) {
      Span work{
        .name = RecEventTrace::toString(event.d_event),
        .trace_id = span.trace_id,
        .parent_span_id = span.span_id,
        .start_time_unix_nano = static_cast<uint64_t>(event.d_ts + diff),
        .end_time_unix_nano = static_cast<uint64_t>(event.d_ts + diff),
      };
      random(work.span_id);
      ret.emplace_back(work);
      pairs[event.d_event] = ret.size() - 1;
    }
    else {
      if (auto startEvent = pairs.find(event.d_event); startEvent != pairs.end()) {
        auto& work = ret.at(startEvent->second);
        if (!std::holds_alternative<std::nullopt_t>(event.d_value)) {
          if (std::holds_alternative<bool>(event.d_value)) {
            work.attributes.emplace_back(KeyValue{"value", {std::get<bool>(event.d_value)}});
          }
          else if (std::holds_alternative<int64_t>(event.d_value)) {
            work.attributes.emplace_back(KeyValue{"value", {std::get<int64_t>(event.d_value)}});
          }
          else if (std::holds_alternative<std::string>(event.d_value)) {
            work.attributes.emplace_back(KeyValue{"value", {std::get<std::string>(event.d_value)}});
          }
          else {
            work.attributes.emplace_back(KeyValue{"value", {toString(event.d_value)}});
          }
        }
        work.end_time_unix_nano = static_cast<uint64_t>(event.d_ts + diff);
        pairs.erase(event.d_event);
      }
    }
  }
  return ret;
}
