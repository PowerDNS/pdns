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
#include "config.h"
#include "remote_logger.hh"

#ifdef HAVE_FSTRM

#include <unordered_map>
#include <fstrm.h>
#include <fstrm/iothr.h>
#include <fstrm/unix_writer.h>
#ifdef HAVE_FSTRM_TCP_WRITER_INIT
#include <fstrm/tcp_writer.h>
#endif

class FrameStreamLogger : public RemoteLoggerInterface, boost::noncopyable
{
public:
  FrameStreamLogger(int family, const std::string& address, bool connect, const std::unordered_map<string,unsigned>& options = std::unordered_map<string,unsigned>());
  virtual ~FrameStreamLogger();
  virtual void queueData(const std::string& data) override;
  virtual std::string toString() const override
  {
    return "FrameStreamLogger to " + d_address;
  }

private:

  const int d_family;
  const std::string d_address;
  struct fstrm_iothr_queue *d_ioqueue{nullptr};
  struct fstrm_writer_options *d_fwopt{nullptr};
  struct fstrm_unix_writer_options *d_uwopt{nullptr};
#ifdef HAVE_FSTRM_TCP_WRITER_INIT
  struct fstrm_tcp_writer_options *d_twopt{nullptr};
#endif
  struct fstrm_writer *d_writer{nullptr};
  struct fstrm_iothr_options *d_iothropt{nullptr};
  struct fstrm_iothr *d_iothr{nullptr};

  void cleanup();
};

#else
class FrameStreamLogger : public RemoteLoggerInterface, boost::noncopyable {};
#endif /* HAVE_FSTRM */
