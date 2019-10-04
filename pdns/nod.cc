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

#include "nod.hh"
#include <fstream>
#include "pdnsexception.hh"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <thread>
#include "threadname.hh"
#include <unistd.h>
#include <boost/filesystem.hpp>
#include "logger.hh"
#include "misc.hh"

using namespace nod;
using namespace boost::filesystem;

// PersistentSBF Implementation 

std::mutex PersistentSBF::d_cachedir_mutex;

// This looks for an old (per-thread) snapshot. The first one it finds,
// it restores from that. Then immediately snapshots with the current thread id,// before removing the old snapshot
// In this way, we can have per-thread SBFs, but still snapshot and restore.
// The mutex has to be static because we can't have multiple (i.e. per-thread)
// instances iterating and writing to the cache dir at the same time
bool PersistentSBF::init(bool ignore_pid) {
  if (d_init)
    return false;

  std::lock_guard<std::mutex> lock(d_cachedir_mutex);
  if (d_cachedir.length()) {
    path p(d_cachedir);
    try {
      if (exists(p) && is_directory(p)) {
        path newest_file;
        std::time_t newest_time=time(nullptr);
        Regex file_regex(d_prefix + ".*\\." + bf_suffix + "$");
        for (directory_iterator i(p); i!=directory_iterator(); ++i) {
          if (is_regular_file(i->path()) &&
              file_regex.match(i->path().filename().string())) {
            if (ignore_pid ||
                (i->path().filename().string().find(std::to_string(getpid())) == std::string::npos)) {
              // look for the newest file matching the regex
              if ((last_write_time(i->path()) < newest_time) ||
                  newest_file.empty()) {
                newest_time = last_write_time(i->path());
                newest_file = i->path();
              }
            }
          }
        }
        if (exists(newest_file)) {
          std::string filename = newest_file.string();
          std::ifstream infile;
          try {
            infile.open(filename, std::ios::in | std::ios::binary);
            g_log << Logger::Warning << "Found SBF file " << filename << endl;
            // read the file into the sbf
            d_sbf.restore(infile);
            infile.close();
            // now dump it out again with new thread id & process id
            snapshotCurrent(std::this_thread::get_id());
            // Remove the old file we just read to stop proliferation
            remove(newest_file);
          }
          catch (const std::runtime_error& e) {
            g_log<<Logger::Warning<<"NODDB init: Cannot parse file: " << filename << endl;
          }
        }
      }
    }
    catch (const filesystem_error& e) {
      g_log<<Logger::Warning<<"NODDB init failed:: " << e.what() << endl;
      return false;
    }
  }
  d_init = true;
  return true;
}

void PersistentSBF::setCacheDir(const std::string& cachedir)
{
  if (!d_init) {
    path p(cachedir);
    if (!exists(p))
      throw PDNSException("NODDB setCacheDir specified non-existent directory: " + cachedir);
    else if (!is_directory(p))
      throw PDNSException("NODDB setCacheDir specified a file not a directory: " + cachedir);
    d_cachedir = cachedir;
  }
}

// Dump the SBF to a file
// To spend the least amount of time inside the mutex, we dump to an
// intermediate stringstream, otherwise the lock would be waiting for
// file IO to complete
bool PersistentSBF::snapshotCurrent(std::thread::id tid)
{
  if (d_cachedir.length()) {
    path p(d_cachedir);
    path f(d_cachedir);
    std::stringstream ss;
    ss << d_prefix << "_" << tid;
    f /= ss.str() + "_" + std::to_string(getpid()) + "." + bf_suffix;
    if (exists(p) && is_directory(p)) {
      try {
        std::ofstream ofile;
        std::stringstream iss;
        ofile.open(f.string(), std::ios::out | std::ios::binary);
        {
          // only lock while dumping to a stringstream
          std::lock_guard<std::mutex> lock(d_sbf_mutex);
          d_sbf.dump(iss);
        }
        // Now write it out to the file
        ofile << iss.str();

        if (ofile.fail())
          throw std::runtime_error("Failed to write to file:" + f.string());
        return true;
      }
      catch (const std::runtime_error& e) {
        g_log<<Logger::Warning<<"NODDB snapshot: Cannot write file: " << e.what() << endl;
      }
    }
    else {
      g_log<<Logger::Warning<<"NODDB snapshot: Cannot write file: " << f.string() << endl;
    }
  }
  return false;
}

// NODDB Implementation

void NODDB::housekeepingThread(std::thread::id tid)
{
  setThreadName("pdns-r/NOD-hk");
  for (;;) {
    sleep(d_snapshot_interval);
    {
      snapshotCurrent(tid);
    }
  }
}

bool NODDB::isNewDomain(const std::string& domain)
{
  DNSName dname(domain);
  return isNewDomain(dname);
}

bool NODDB::isNewDomain(const DNSName& dname)
{
  std::string dname_lc = dname.toDNSStringLC();
  // The only time this should block is when snapshotting from the
  // housekeeping thread
  // the result is always the inverse of what is returned by the SBF
  return !d_psbf.testAndAdd(dname_lc);
}

bool NODDB::isNewDomainWithParent(const std::string& domain, std::string& observed)
{
  DNSName dname(domain);
  return isNewDomainWithParent(dname, observed);
}

bool NODDB::isNewDomainWithParent(const DNSName& dname, std::string& observed)
{
  bool ret = isNewDomain(dname);
  if (ret == true) {
    DNSName mdname = dname;
    while (mdname.chopOff()) {
      if (!isNewDomain(mdname)) {
        observed = mdname.toString();
        break;
      }
    }
  }
  return ret;
}

void NODDB::addDomain(const DNSName& dname)
{
  std::string native_domain = dname.toDNSStringLC();
  d_psbf.add(native_domain);
}

void NODDB::addDomain(const std::string& domain)
{
  DNSName dname(domain);
  addDomain(dname);
}

// UniqueResponseDB Implementation
bool UniqueResponseDB::isUniqueResponse(const std::string& response)
{
  return !d_psbf.testAndAdd(response);
}

void UniqueResponseDB::addResponse(const std::string& response)
{
  d_psbf.add(response);
}

void UniqueResponseDB::housekeepingThread(std::thread::id tid)
{
  setThreadName("pdns-r/UDR-hk");
  for (;;) {
    sleep(d_snapshot_interval);
    {
      snapshotCurrent(tid);
    }
  }
}
