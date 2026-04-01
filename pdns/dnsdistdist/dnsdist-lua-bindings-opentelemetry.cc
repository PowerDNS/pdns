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

namespace pdns::trace::dnsdist
{
void emptyLuaTracing(LuaContext& luaCtx)
{
  luaCtx.writeFunction<void(const std::string&, const std::function<void()>&)>(
    "withTraceSpan",
    []([[maybe_unused]] const std::string& name, const std::function<void()>& luaFunc) {
      luaFunc();
    });

  luaCtx.writeFunction<void(const std::string&, const std::string&)>(
    "setSpanAttribute",
    []([[maybe_unused]] const std::string& key, [[maybe_unused]] const std::string& value) {
      return;
    });
};

void setupLuaTracing(LuaContext& luaCtx, std::shared_ptr<Tracer>& tracer)
{
  if (tracer == nullptr) {
    return;
  }

  luaCtx.writeFunction<void(const std::string&, const std::function<void()>&)>(
    "withTraceSpan",
    [&tracer]([[maybe_unused]] const std::string& name, [[maybe_unused]] const std::function<void()>& luaFunc) {
#ifndef DISABLE_PROTOBUF
      auto closer = tracer->openSpan(name);
      luaFunc();
      return;
#endif
      luaFunc();
    });

  luaCtx.writeFunction<void(const std::string&, const std::string&)>(
    "setSpanAttribute",
    [&tracer]([[maybe_unused]] const std::string& key, [[maybe_unused]] const std::string& value) {
#ifndef DISABLE_PROTOBUF
      tracer->setSpanAttribute(tracer->getLastSpanID(), key, AnyValue{value});
#endif
      return;
    });
}

} // namespace pdns::trace::dnsdist
