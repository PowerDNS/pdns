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

#include <cstring>
#include <stdexcept>

#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

#include "capabilities.hh"
#include "misc.hh"

void dropCapabilities(std::set<std::string> capabilitiesToKeep)
{
#ifdef HAVE_LIBCAP
   cap_t caps = cap_get_proc();
   if (caps != nullptr) {
     cap_clear(caps);

     if (!capabilitiesToKeep.empty()) {
       std::vector<cap_value_t> toKeep;
       toKeep.reserve(capabilitiesToKeep.size());

       for (const auto& capToKeep : capabilitiesToKeep) {
         cap_value_t value;
         int res = cap_from_name(capToKeep.c_str(), &value);
         if (res != 0) {
           cap_free(caps);
           throw std::runtime_error("Unable to convert capability name '" + capToKeep + "': " + stringerror());
         }
         toKeep.push_back(value);
       }

       if (cap_set_flag(caps, CAP_EFFECTIVE, toKeep.size(), toKeep.data(), CAP_SET) != 0) {
         cap_free(caps);
         throw std::runtime_error("Unable to set effective flag capabilities: " + stringerror());
       }

       if (cap_set_flag(caps, CAP_PERMITTED, toKeep.size(), toKeep.data(), CAP_SET) != 0) {
         cap_free(caps);
         throw std::runtime_error("Unable to set permitted flag capabilities: " + stringerror());
       }
     }

     if (cap_set_proc(caps) != 0) {
       cap_free(caps);
       throw std::runtime_error("Unable to drop capabilities: " + stringerror());
     }

     cap_free(caps);
   }
#endif /* HAVE_LIBCAP */
}
