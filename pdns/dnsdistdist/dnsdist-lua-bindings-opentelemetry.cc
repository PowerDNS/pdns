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

#include "dnsdist-lua-bindings-opentelemetry.hh"
#include "dnsdist-opentelemetry.hh"
#include <memory>

extern std::shared_ptr<pdns::trace::dnsdist::Tracer> g_otTracer;

namespace pdns::trace::dnsdist
{
void setupGlobalLuaTracing(LuaContext& luaCtx)
{
  luaCtx.writeFunction<void(const std::string&, const std::function<void()>&)>(
    "withTraceSpan",
    []([[maybe_unused]] const std::string& name, [[maybe_unused]] const std::function<void()>& luaFunc) {
#ifndef DISABLE_PROTOBUF
      if (g_otTracer == nullptr) {
        luaFunc();
        return;
      }
      auto closer = g_otTracer->openSpan(name);
#endif
      luaFunc();
    });

  luaCtx.writeFunction<void(const std::string&, const std::string&)>(
    "setSpanAttribute",
    []([[maybe_unused]] const std::string& key, [[maybe_unused]] const std::string& value) {
#ifndef DISABLE_PROTOBUF
      if (g_otTracer != nullptr) {
        g_otTracer->setSpanAttribute(g_otTracer->getLastSpanID(), key, AnyValue{value});
      }
#endif
      return;
    });
}

void setupLuaTracing(LuaContext& luaCtx, std::shared_ptr<Tracer>& tracer)
{
  luaCtx.writeFunction<void(const std::string&, const std::function<void()>&)>(
    "withTraceSpan",
    [&tracer]([[maybe_unused]] const std::string& name, [[maybe_unused]] const std::function<void()>& luaFunc) {
#ifndef DISABLE_PROTOBUF
      if (tracer == nullptr) {
        luaFunc();
        return;
      }
      auto closer = tracer->openSpan(name);
#endif
      luaFunc();
    });

  luaCtx.writeFunction<void(const std::string&, const std::string&)>(
    "setSpanAttribute",
    [&tracer]([[maybe_unused]] const std::string& key, [[maybe_unused]] const std::string& value) {
#ifndef DISABLE_PROTOBUF
      if (tracer != nullptr) {
        tracer->setSpanAttribute(tracer->getLastSpanID(), key, AnyValue{value});
      }
#endif
      return;
    });
}

} // namespace pdns::trace::dnsdist
