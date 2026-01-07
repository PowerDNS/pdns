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

#include "rec_channel.hh"

#include <sys/socket.h>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "misc.hh"
#include "namespaces.hh"
#include "pdnsexception.hh"
#include "sanitizer.hh"

std::atomic<bool> RecursorControlChannel::stop = false;

RecursorControlChannel::RecursorControlChannel() :
  d_fd(-1)
{
  memset(&d_local, 0, sizeof(d_local));
}

RecursorControlChannel::~RecursorControlChannel()
{
  if (d_fd > 0) {
    close(d_fd);
  }
  if (d_local.sun_path[0] != '\0') {
    unlink(d_local.sun_path); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  }
}

int RecursorControlChannel::listen(const string& filename)
{
  d_fd = socket(AF_UNIX, SOCK_STREAM, 0);

  if (d_fd < 0) {
    throw PDNSException("Creating UNIX domain socket: " + stringerror());
  }
  setCloseOnExec(d_fd);

  int tmp = 1;
  if (setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof tmp) < 0) {
    throw PDNSException("Setsockopt failed: " + stringerror());
  }

  int err = unlink(filename.c_str());
  if (err < 0 && errno != ENOENT) {
    throw PDNSException("Can't remove (previous) controlsocket '" + filename + "': " + stringerror() + " (try --socket-dir)");
  }

  if (makeUNsockaddr(filename, &d_local) != 0) {
    throw PDNSException("Unable to bind to controlsocket, path '" + filename + "' is not a valid UNIX socket path.");
  }

  if (bind(d_fd, reinterpret_cast<sockaddr*>(&d_local), sizeof(d_local)) < 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    throw PDNSException("Unable to bind to controlsocket '" + filename + "': " + stringerror());
  }
  if (::listen(d_fd, 0) == -1) {
    throw PDNSException("Unable to listen on controlsocket '" + filename + "': " + stringerror());
  }
  return d_fd;
}

void RecursorControlChannel::connect(const string& path, const string& filename)
{
  struct sockaddr_un remote{};

  d_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  setCloseOnExec(d_fd);

  if (d_fd < 0) {
    throw PDNSException("Creating UNIX domain socket: " + stringerror());
  }
  try {
    int tmp = 1;
    if (setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof tmp) < 0) {
      throw PDNSException("Setsockopt failed: " + stringerror());
    }

    string remotename = path + "/" + filename;
    if (makeUNsockaddr(remotename, &remote) != 0) {
      throw PDNSException("Unable to connect to controlsocket, path '" + remotename + "' is not a valid UNIX socket path.");
    }

    if (::connect(d_fd, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) < 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      if (d_local.sun_path[0] != '\0') {
        unlink(d_local.sun_path); // NOLINT
      }
      throw PDNSException("Unable to connect to remote '" + remotename + "': " + stringerror());
    }
  }
  catch (...) {
    close(d_fd);
    d_fd = -1;
    d_local.sun_path[0] = 0;
    throw;
  }
}

static void sendfd(int socket, int fd_to_pass)
{
  struct msghdr msg{};
  struct cmsghdr* cmsg{};
  union
  {
    struct cmsghdr hdr;
    std::array<unsigned char, CMSG_SPACE(sizeof(int))> buf;
  } cmsgbuf{};
  std::array<iovec, 1> io_vector{};
  char character = 'X';

  io_vector[0].iov_base = &character;
  io_vector[0].iov_len = 1;

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = cmsgbuf.buf.data();
  msg.msg_controllen = cmsgbuf.buf.size();
  msg.msg_iov = io_vector.data();
  msg.msg_iovlen = io_vector.size();

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  *reinterpret_cast<int*>(CMSG_DATA(cmsg)) = fd_to_pass; // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

  if (sendmsg(socket, &msg, 0) == -1) {
    throw PDNSException("Unable to send fd message over control channel: " + stringerror());
  }
}

void RecursorControlChannel::send(int fileDesc, const Answer& msg, unsigned int timeout, int fd_to_pass)
{
  int ret = waitForRWData(fileDesc, false, static_cast<int>(timeout), 0);
  if (ret == 0) {
    throw PDNSException("Timeout sending message over control channel");
  }
  if (ret < 0) {
    throw PDNSException("Error sending message over control channel:" + stringerror());
  }

  if (::send(fileDesc, &msg.d_ret, sizeof(msg.d_ret), 0) < 0) {
    throw PDNSException("Unable to send return code over control channel: " + stringerror());
  }
  size_t len = msg.d_str.length();
  if (::send(fileDesc, &len, sizeof(len), 0) < 0) {
    throw PDNSException("Unable to send length over control channel: " + stringerror());
  }
  if (::send(fileDesc, msg.d_str.c_str(), len, 0) != static_cast<ssize_t>(len)) {
    throw PDNSException("Unable to send message over control channel: " + stringerror());
  }

  if (fd_to_pass != -1) {
    sendfd(fileDesc, fd_to_pass);
  }
}

static void waitForRead(int fileDesc, unsigned int timeout, time_t start)
{
  time_t elapsed = time(nullptr) - start;
  if (elapsed >= timeout) {
    throw PDNSException("Timeout waiting for control channel data");
  }
  // coverity[store_truncates_time_t]
  int ret = waitForData(fileDesc, static_cast<int>(timeout - static_cast<unsigned int>(elapsed)), 0);
  if (ret == 0) {
    throw PDNSException("Timeout waiting for control channel data");
  }
}

static size_t getArgMax()
{
#if defined(ARG_MAX)
  return ARG_MAX;
#endif

#if defined(_SC_ARG_MAX)
  auto tmp = sysconf(_SC_ARG_MAX);
  if (tmp != -1) {
    return tmp;
  }
#endif
  /* _POSIX_ARG_MAX */
  return 4096;
}

RecursorControlChannel::Answer RecursorControlChannel::recv(int fileDesc, unsigned int timeout)
{
  // timeout covers the operation of all read ops combined
  const time_t start = time(nullptr);

  waitForRead(fileDesc, timeout, start);
  int err{};
  auto ret = ::recv(fileDesc, &err, sizeof(err), 0);
  if (ret == 0) {
#if defined(__SANITIZE_THREAD__)
    return {0, "bye nicely\n"}; // Hack because TSAN enabled build justs _exits on quit-nicely
#endif
    throw PDNSException("Unable to receive status over control connection: EOF");
  }
  if (ret != sizeof(err)) {
    throw PDNSException("Unable to receive return status over control channel: " + stringerror());
  }

  waitForRead(fileDesc, timeout, start);
  size_t len{};
  if (::recv(fileDesc, &len, sizeof(len), 0) != sizeof(len)) {
    throw PDNSException("Unable to receive length over control channel: " + stringerror());
  }

  if (len > getArgMax()) {
    throw PDNSException("Length of control channel message too large");
  }

  string str;
  str.reserve(len);
  while (str.length() < len) {
    std::array<char, 1024> buffer{};
    waitForRead(fileDesc, timeout, start);
    size_t toRead = std::min(len - str.length(), buffer.size());
    ssize_t recvd = ::recv(fileDesc, buffer.data(), toRead, 0);
    if (recvd <= 0) {
      // EOF means we have a length error
      throw PDNSException("Unable to receive message over control channel: " + stringerror());
    }
    str.append(buffer.data(), recvd);
  }

  return {err, std::move(str)};
}
