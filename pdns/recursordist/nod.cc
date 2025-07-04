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
#include <cstdlib>
#include "logger.hh"
#include "logging.hh"
#include "misc.hh"

using namespace nod;
namespace filesystem = boost::filesystem;

// PersistentSBF Implementation

std::mutex PersistentSBF::d_cachedir_mutex;

void PersistentSBF::remove_tmp_files(const filesystem::path& path, std::scoped_lock<std::mutex>& /* lock */)
{
  Regex file_regex(d_prefix + ".*\\." + bf_suffix + "\\..{8}$");
  for (const auto& file : filesystem::directory_iterator(path)) {
    if (filesystem::is_regular_file(file.path()) && file_regex.match(file.path().filename().string())) {
      filesystem::remove(file);
    }
  }
}

// This looks for the newest (per-thread) snapshot it can find and it restores from that. Then
// immediately snapshots with the current thread id, before removing the old snapshot.
// In this way, we can have per-thread SBFs, but still snapshot and restore.  The mutex has to be
// static because we can't have multiple (i.e. per-thread) instances iterating and writing to the
// cache dir at the same time
bool PersistentSBF::init(bool ignore_pid)
{
  auto log = g_slog->withName("nod");
  std::scoped_lock<std::mutex> lock(d_cachedir_mutex);
  if (d_cachedir.length() != 0) {
    filesystem::path path(d_cachedir);
    try {
      if (filesystem::exists(path) && filesystem::is_directory(path)) {
        remove_tmp_files(path, lock);
        filesystem::path newest_file;
        std::time_t newest_time = 0;
        Regex file_regex(d_prefix + ".*\\." + bf_suffix + "$");
        for (const auto& file : filesystem::directory_iterator(path)) {
          if (filesystem::is_regular_file(file.path()) && file_regex.match(file.path().filename().string())) {
            if (ignore_pid || (file.path().filename().string().find(std::to_string(getpid())) == std::string::npos)) {
              // look for the newest file matching the regex
              if (last_write_time(file.path()) > newest_time) {
                newest_time = last_write_time(file.path());
                newest_file = file.path();
              }
            }
          }
        }
        if (!newest_file.empty() && filesystem::exists(newest_file)) {
          const std::string& filename = newest_file.string();
          std::ifstream infile;
          try {
            infile.open(filename, std::ios::in | std::ios::binary);
            SLOG(g_log << Logger::Warning << "Found SBF file " << filename << endl,
                 log->info(Logr::Warning, "Found SBF File", "file", Logging::Loggable(filename)));
            // read the file into the sbf
            d_sbf.lock()->restore(infile);
            infile.close();
            // now dump it out again with new thread id & process id
            snapshotCurrent(std::this_thread::get_id());
            // Remove the old file we just read to stop proliferation
            filesystem::remove(newest_file);
          }
          catch (const std::runtime_error& e) {
            infile.close();
            filesystem::remove(newest_file);
            SLOG(g_log << Logger::Warning << "NODDB init: Cannot parse file: " << filename << ": " << e.what() << "; removed" << endl,
                 log->error(Logr::Warning, e.what(), "NODDB init: Cannot parse file, removed", "file", Logging::Loggable(filename)));
          }
        }
      }
    }
    catch (const filesystem::filesystem_error& e) {
      SLOG(g_log << Logger::Warning << "NODDB init failed: " << e.what() << endl,
           log->error(Logr::Warning, e.what(), "NODDB init failed", "exception", Logging::Loggable("filesystem::filesystem_error")));
      return false;
    }
  }
  return true;
}

void PersistentSBF::setCacheDir(const std::string& cachedir)
{
  filesystem::path path(cachedir);
  if (!exists(path)) {
    throw PDNSException("NODDB setCacheDir specified nonexistent directory: " + cachedir);
  }
  if (!is_directory(path)) {
    throw PDNSException("NODDB setCacheDir specified a file not a directory: " + cachedir);
  }
  d_cachedir = cachedir;
}

// Dump the SBF to a file
// To spend the least amount of time inside the mutex, we dump to an
// intermediate stringstream, otherwise the lock would be waiting for
// file IO to complete
bool PersistentSBF::snapshotCurrent(std::thread::id tid)
{
  auto log = g_slog->withName("nod");
  if (d_cachedir.length() != 0) {
    filesystem::path path(d_cachedir);
    filesystem::path file(d_cachedir);
    std::stringstream strStream;
    strStream << d_prefix << "_" << tid;
    file /= strStream.str() + "_" + std::to_string(getpid()) + "." + bf_suffix;
    if (filesystem::exists(path) && filesystem::is_directory(path)) {
      try {
        std::ostringstream oss;
        {
          // only lock while dumping to a stringstream
          d_sbf.lock()->dump(oss);
        }
        // Now write it out to the file
        std::string ftmp = file.string() + ".XXXXXXXX";
        auto fileDesc = FDWrapper(mkstemp(ftmp.data()));
        if (fileDesc == -1) {
          throw std::runtime_error("Cannot create temp file: " + stringerror());
        }
        const std::string str = oss.str(); // XXX creates a copy, with c++20 we can use view()
        ssize_t len = write(fileDesc, str.data(), str.length());
        if (len != static_cast<ssize_t>(str.length())) {
          filesystem::remove(ftmp.c_str());
          throw std::runtime_error("Failed to write to file:" + ftmp);
        }
        if (fileDesc.reset() != 0) {
          filesystem::remove(ftmp);
          throw std::runtime_error("Failed to write to file:" + ftmp);
        }
        try {
          filesystem::rename(ftmp, file);
        }
        catch (const std::runtime_error& e) {
          SLOG(g_log << Logger::Warning << "NODDB snapshot: Cannot rename file: " << e.what() << endl,
               log->error(Logr::Warning, e.what(), "NODDB snapshot: Cannot rename file", "exception", Logging::Loggable("std::runtime_error")));
          filesystem::remove(ftmp);
          throw;
        }
        return true;
      }
      catch (const std::runtime_error& e) {
        SLOG(g_log << Logger::Warning << "NODDB snapshot: Cannot write file: " << e.what() << endl,
             log->error(Logr::Warning, e.what(), "NODDB snapshot: Cannot write file", "exception", Logging::Loggable("std::runtime_error")));
      }
    }
    else {
      SLOG(g_log << Logger::Warning << "NODDB snapshot: Cannot write file: " << file.string() << endl,
           log->info(Logr::Warning, "NODDB snapshot: Cannot write file", "file", Logging::Loggable(file.string())));
    }
  }
  return false;
}

// NODDB Implementation

void NODDB::housekeepingThread(std::thread::id tid)
{
  setThreadName("rec/nod-hk");
  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(d_snapshot_interval));
    snapshotCurrent(tid);
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
  if (ret) {
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
  setThreadName("rec/udr-hk");
  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(d_snapshot_interval));
    snapshotCurrent(tid);
  }
}
