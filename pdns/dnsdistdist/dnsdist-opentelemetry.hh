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

#include <memory>
#include <string>
#include <vector>

#ifndef DISABLE_PROTOBUF
#include "protozero-trace.hh"
using TraceID = pdns::trace::TraceID;
using SpanID = pdns::trace::SpanID;
using AnyValue = pdns::trace::AnyValue;
using TracesData = pdns::trace::TracesData;
#else
// Define the minimal things needed
#include <variant>
using TraceID = int;
using SpanID = int;
using AnyValue = std::variant<std::string, int>;
using TracesData = int;
#endif

#include "lock.hh"

/*
 * This namespace contains all the bits and pieces required to do OpenTelemetry
 * traces in dnsdist. It is contained in this header and cc-file to ensure the rest
 * of the code is not littered with #ifdefs for DISABLE_PROTOBUF. All functions and
 * other public members can be safely called/manipulated in a non-protobuf build of
 * dnsdist.
 *
 * The idea is inspired by the rec-eventtrace.{cc,hh} files.
 *
 * Although the namespace contains dnsdist, it might be general enough to be
 * reused (after renaming the namespace) by auth and recursor
 */
namespace pdns::trace::dnsdist
{

/**
 * @class Tracer
 * @brief This class holds a single trace instance
 *
 */
class Tracer : public std::enable_shared_from_this<Tracer>
{
public:
  ~Tracer() = default;
  Tracer(const Tracer&) = delete;
  Tracer& operator=(const Tracer) = delete;
  Tracer& operator=(Tracer&&) = delete;
  Tracer(Tracer&&) = delete;

  /**
   * @brief get a new Tracer
   */
  static std::shared_ptr<Tracer> getTracer()
  {
    return std::shared_ptr<Tracer>(new Tracer);
  }

  /**
   * @brief Activate the Tracer
   *
   * Once activated, all new events are stored as actual Spans
   */
  void activate()
  {
#ifndef DISABLE_PROTOBUF
    d_activated = true;
    if (d_traceid == pdns::trace::s_emptyTraceID) {
      d_traceid.makeRandom();
    }
#endif
  }

  /**
   * @brief Deactivate the tracer
   */
  void deactivate()
  {
#ifndef DISABLE_PROTOBUF
    // Set deactivated, but don't delete any data.
    // The Tracer can be activated later
    d_activated = false;
#endif
  }

  /**
   * @brief Add an attribute to the Trace
   *
   * This only works when Tracer is active
   *
   * @param key
   * @param value
   * @return true on success, false when attribute was not added
   */
  bool setTraceAttribute(const std::string& key, const AnyValue& value);

  /**
   * @brief Set an attribute on a Span
   *
   * This does not work when the Tracer is not active
   *
   * @param spanID The SpanID of the Span to add the attribute to
   * @param key
   * @param value
   */
  void setSpanAttribute(const SpanID& spanID, const std::string& key, const AnyValue& value);

  /**
   * @brief Sets the stop timestamp for a span
   *
   * When a Span is already closed, the timestamp is not updated
   *
   * @param spanID The ID of the Span to set the end time for
   */
  void closeSpan(const SpanID& spanID);

  /**
   * @brief Get the last SpanID generated
   *
   * @return The last generated SpanID, or empty SpanID when none exist
   */
  [[nodiscard]] SpanID getLastSpanID();

  /**
   * @brief Get the SpanID for the most recently added span with a name
   *
   * @param name The name of the Span
   * @return The SpanID, or empty SpanID when none are found
   */
  [[nodiscard]] SpanID getLastSpanIDForName(const std::string& name);

  /**
   * @brief Retrieve the TraceID for this Tracer
   */
  [[nodiscard]] TraceID getTraceID() const;

  /**
   * @brief Generate the TracesData from all data in this Tracer
   *
   * @return pdns::trace::TracesData
   */
  [[nodiscard]] TracesData getTracesData();

  /**
   * @brief Get the TracesData as protobuf encoded OpenTelemetry data
   */
  [[nodiscard]] std::string getOTProtobuf();

  /**
   * @class Closer
   * @brief Automatically closes a Span when it goes out of scope
   *
   * This is a helper that _somewhat_ implements Go's `defer` in C++ semantics
   * Basically, it stores a pointer to the Tracer and a SpanID.
   * When the object goes out of scope, the closeSpan function is called
   */
  class Closer
  {
  public:
    /**
     * @brief An empty Closer, not really useful
     */
    Closer() = default;

#ifndef DISABLE_PROTOBUF
    /**
     * @brief Create a Closer
     *
     * There should be no need to call this directly. Use one of these functions to get one:
     *
     * Tracer::getCloser
     * Tracer::openSpan
     *
     * @param tracer A pointer to the Tracer where we want to close a Span
     * @param spanid The SpanID to close in the Tracer
     */
    Closer(std::shared_ptr<Tracer> tracer, const SpanID& spanid) :
      d_tracer(std::move(tracer)), d_spanID(spanid) {};
#endif

    /**
     * @brief Closes the Span in the Tracer
     */
    ~Closer()
    {
#ifndef DISABLE_PROTOBUF
      if (d_tracer != nullptr) {
        d_tracer->closeSpan(d_spanID);
      }
#endif
    };
    Closer(const Closer&) = default;
    Closer& operator=(const Closer&) = default;
    Closer& operator=(Closer&&) noexcept = default;
    Closer(Closer&&) = default;

    /**
     * @brief Get the SpanID
     *
     * @return
     */
    [[nodiscard]] SpanID getSpanID() const;

  private:
#ifndef DISABLE_PROTOBUF
    std::shared_ptr<Tracer> d_tracer{nullptr};
    SpanID d_spanID{};
#endif
  };

  /**
   * @brief Get a Closer for spanid in this Tracer
   *
   * @param spanid The SpanID that will close when the Closer is destructed
   * @return Tracer::Closer
   */
  Closer getCloser(const SpanID& spanid);

  /**
   * @brief Add a new Span
   *
   * @param name The name for this span
   * @return Tracer::Closer for the newly created Span
   */
  Closer openSpan(const std::string& name);

  /**
   * @brief Add a new Span which is a child of another Span
   *
   * @param name The name for this span
   * @param parentSpanID The SpanID of the parent Trace
   * @return Tracer::Closer for the newly created Span
   */
  Closer openSpan(const std::string& name, const SpanID& parentSpanID);

private:
  Tracer() = default;

  /**
   * @brief Create a new Span
   *
   * The Span's start time is set to the current time
   *
   * @param name The name for this span
   * @return The SpanID of the created Span
   */
  SpanID addSpan(const std::string& name);

  /**
   * @brief Create a new Span with a parent
   *
   * The Span's start time is set to the current time
   *
   * @param name The name for this span
   * @param parentSpanID The SpanID of the parent Span (not verified)
   * @return The SpanID of the created Span
   */
  SpanID addSpan(const std::string& name, const SpanID& parentSpanID);

#ifndef DISABLE_PROTOBUF
  /**
   * @class preActivationSpanInfo
   * @brief Used before the Tracer is activated to store Span information
   */
  struct preActivationSpanInfo
  {
    std::string name;
    SpanID span_id;
    SpanID parent_span_id;
    uint64_t start_time_unix_nano;
    uint64_t end_time_unix_nano;
  };

  /**
   * @brief Stores all preActivationSpanInfos. It is used until d_activated is true
   */
  LockGuarded<std::vector<preActivationSpanInfo>> d_preActivationSpans;
  /**
   * @brief Stores all Spans. It is used when d_activated is true
   */
  LockGuarded<std::vector<Span>> d_postActivationSpans;
  /**
   * @brief All attributes related to this Trace (added to the ScopeSpan)
   */
  std::vector<pdns::trace::KeyValue> d_attributes;

  /**
   * @brief The TraceID for this Tracer. It is stable for the lifetime of the Tracer
   */
  TraceID d_traceid{};
  /**
   * @brief The last SpanID that was added to this Tracer
   */
  SpanID d_lastSpanID{};
  /**
   * @brief Whether or not we are storing full Spans or minimal Spans
   */
  bool d_activated{false};
#endif
};
} // namespace pdns::trace::dnsdist
