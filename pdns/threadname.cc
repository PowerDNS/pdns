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
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>

#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif

#ifdef DNSDIST
#include "dolog.hh"
#else
#include "logger.hh"
#include "logging.hh"
#endif

#include "threadname.hh"

static int trySetThreadName(const std::string& threadName) {
  int retval = 0;

#ifdef HAVE_PTHREAD_SETNAME_NP_2
  retval = pthread_setname_np(pthread_self(), threadName.c_str());
#endif
#ifdef HAVE_PTHREAD_SET_NAME_NP_2
  retval = pthread_set_name_np(pthread_self(), threadName.c_str());
#endif
#ifdef HAVE_PTHREAD_SET_NAME_NP_2_VOID
  pthread_set_name_np(pthread_self(), threadName.c_str());
#endif
#ifdef HAVE_PTHREAD_SETNAME_NP_1
  retval = pthread_setname_np(threadName.c_str());
#endif
#ifdef HAVE_PTHREAD_SETNAME_NP_3
  retval = pthread_setname_np(pthread_self(), threadName.c_str(), nullptr);
#endif

  return retval;
}

void setThreadName(const std::string& threadName) {
  int retval = trySetThreadName(threadName);
  if (retval == ERANGE) {
    const std::string shortThreadName(threadName.substr(0, 15));
    retval = trySetThreadName(shortThreadName);
  }

  if (retval != 0) {
#ifdef DNSDIST
    SLOG(warnlog("Could not set thread name %s for thread: %s", threadName, strerror(retval)),
         dnsdist::logging::getTopLogger("runtime")->error(Logr::Warning, retval, "Could not set thread name", "name", Logging::Loggable(threadName)));
#else
    SLOG(g_log<<Logger::Warning<<"Could not set thread name "<<threadName<<" for thread: "<<strerror(retval)<<endl,
         g_slog->withName("runtime")->error(Logr::Warning, retval, "Could not set thread name", "name", Logging::Loggable(threadName)));
#endif
  }
}
