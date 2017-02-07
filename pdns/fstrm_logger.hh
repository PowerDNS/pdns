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

#include <atomic>
#include <condition_variable>
#include <queue>
#include <thread>

#include "iputils.hh"
#include "remote_logger.hh"

#include <fstrm.h>
#include <fstrm/iothr.h>
#include <fstrm/unix_writer.h>


class FrameStreamLogger : public IfaceRemoteLogger
{
public:
  FrameStreamLogger(const std::string socket_path);
  ~FrameStreamLogger();
  void queueData(const std::string& data);
  std::string toString()
  {
    return socket_path;
  }
private:
  std::string socket_path;
  struct fstrm_writer *writer;
  struct fstrm_writer_options *fwopt;
  struct fstrm_unix_writer_options *uwopt;
  struct fstrm_iothr *iothr;
  struct fstrm_iothr_queue *ioqueue;
};
