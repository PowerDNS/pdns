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
#include "config.h"
#include "coverage.hh"

#ifdef COVERAGE
extern "C"
{
#ifdef CLANG_COVERAGE
  // NOLINTNEXTLINE(bugprone-reserved-identifier): not ours
  int __llvm_profile_write_file(void);
#else /* CLANG_COVERAGE */
  // NOLINTNEXTLINE(bugprone-reserved-identifier): not ours
  void __gcov_dump(void);
#endif /* CLANG_COVERAGE */
}
#endif /* COVERAGE */

namespace pdns::coverage
{
void dumpCoverageData()
{
#ifdef COVERAGE
#ifdef CLANG_COVERAGE
  __llvm_profile_write_file();
#else /* CLANG_COVERAGE */
  __gcov_dump();
#endif /* CLANG_COVERAGE */
#endif /* COVERAGE */
}
}
