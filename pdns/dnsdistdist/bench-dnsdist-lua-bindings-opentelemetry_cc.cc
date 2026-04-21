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
#include <memory>
#define CATCH_CONFIG_NO_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include "dnsdist-opentelemetry.hh"
#include "dnsdist-lua-bindings-opentelemetry.hh"

extern std::shared_ptr<pdns::trace::dnsdist::Tracer> g_otTracer;

TEST_CASE("lua-bindings-opentelemetry-runWithGlobalLuaTracing")
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  size_t testnum = 0;

  BENCHMARK("withTracer")
  {
    return pdns::trace::dnsdist::runWithGlobalLuaTracing(tracer, [&testnum]() {
      return testnum++;
    });
  };

  testnum = 0;
  tracer = nullptr;
  BENCHMARK("withoutTracer")
  {
    return pdns::trace::dnsdist::runWithGlobalLuaTracing(tracer, [&testnum]() {
      return testnum++;
    });
  };
}
