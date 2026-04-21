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

#include "ext/luawrapper/include/LuaContext.hpp"

#include "dnsdist-lua.hh"
#include "dnsdist-opentelemetry.hh"
#include "lock.hh"
#include "misc.hh"

extern std::shared_ptr<pdns::trace::dnsdist::Tracer> g_otTracer;

namespace pdns::trace::dnsdist
{
void setupLuaTracing(LuaContext&, std::shared_ptr<Tracer>&);
void setupGlobalLuaTracing(LuaContext&);

static std::shared_ptr<Tracer> s_emptyTracer{nullptr};

template <typename Func, typename... Args>
auto runWithGlobalLuaTracing(std::shared_ptr<Tracer>& tracer, Func&& func, Args&&... args)
{
  auto luaCtx = g_lua.lock();
  g_otTracer = tracer;
  auto exitGuard = ::pdns::defer([] {
    g_otTracer = s_emptyTracer;
  });
  return std::invoke(std::forward<Func>(func), std::forward<Args>(args)...);
}

template <typename Func, typename... Args>
auto runWithLuaTracing(LuaContext& luaCtx, std::shared_ptr<Tracer>& tracer, Func&& func, Args&&... args)
{
  setupLuaTracing(luaCtx, tracer);
  auto exitGuard = ::pdns::defer([&luaCtx] {
    setupLuaTracing(luaCtx, s_emptyTracer);
  });
  return std::invoke(std::forward<Func>(func), std::forward<Args>(args)...);
}
} // namespace pdns::trace::dnsdist
