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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "remotebackend.hh"
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

UnixsocketConnector::UnixsocketConnector(std::map<std::string, std::string> optionsMap)
{
  if (optionsMap.count("path") == 0) {
    g_log << Logger::Error << "Cannot find 'path' option in connection string" << endl;
    throw PDNSException();
  }
  this->timeout = 2000;
  if (optionsMap.find("timeout") != optionsMap.end()) {
    this->timeout = std::stoi(optionsMap.find("timeout")->second);
  }
  this->path = optionsMap.find("path")->second;
  this->options = optionsMap;
  this->connected = false;
  this->fd = -1;
}

UnixsocketConnector::~UnixsocketConnector()
{
  if (this->connected) {
    try {
      g_log << Logger::Info << "closing socket connection" << endl;
    }
    catch (...) {
    }
    close(fd);
  }
}

int UnixsocketConnector::send_message(const Json& input)
{
  auto data = input.dump() + "\n";
  int rv = this->write(data);
  if (rv == -1)
    return -1;
  return rv;
}

int UnixsocketConnector::recv_message(Json& output)
{
  int rv;
  std::string s_output, err;

  struct timeval t0, t;

  gettimeofday(&t0, NULL);
  memcpy(&t, &t0, sizeof(t0));
  s_output = "";

  while ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_usec - t0.tv_usec) / 1000 < this->timeout) {
    int avail = waitForData(this->fd, 0, this->timeout * 500); // use half the timeout as poll timeout
    if (avail < 0) // poll error
      return -1;
    if (avail == 0) { // timeout
      gettimeofday(&t, NULL);
      continue;
    }

    rv = this->read(s_output);
    if (rv == -1)
      return -1;

    if (rv > 0) {
      // see if it can be parsed
      output = Json::parse(s_output, err);
      if (output != nullptr)
        return s_output.size();
    }
    gettimeofday(&t, NULL);
  }

  close(fd);
  connected = false; // we need to reconnect
  return -1;
}

ssize_t UnixsocketConnector::read(std::string& data)
{
  ssize_t nread;
  char buf[1500] = {0};

  reconnect();
  if (!connected)
    return -1;
  nread = ::read(this->fd, buf, sizeof buf);

  // just try again later...
  if (nread == -1 && errno == EAGAIN)
    return 0;

  if (nread == -1 || nread == 0) {
    connected = false;
    close(fd);
    return -1;
  }

  data.append(buf, nread);
  return nread;
}

ssize_t UnixsocketConnector::write(const std::string& data)
{
  size_t pos = 0;

  reconnect();
  if (!connected)
    return -1;

  while (pos < data.size()) {
    ssize_t written = ::write(fd, &data.at(pos), data.size() - pos);
    if (written < 1) {
      connected = false;
      close(fd);
      return -1;
    }
    else {
      pos = pos + static_cast<size_t>(written);
    }
  }
  return pos;
}

void UnixsocketConnector::reconnect()
{
  struct sockaddr_un sock;
  int rv;

  if (connected)
    return; // no point reconnecting if connected...
  connected = true;

  g_log << Logger::Info << "Reconnecting to backend" << std::endl;
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    connected = false;
    g_log << Logger::Error << "Cannot create socket: " << strerror(errno) << std::endl;
    ;
    return;
  }

  if (makeUNsockaddr(path, &sock)) {
    g_log << Logger::Error << "Unable to create UNIX domain socket: Path '" << path << "' is not a valid UNIX socket path." << std::endl;
    return;
  }

  rv = connect(fd, reinterpret_cast<struct sockaddr*>(&sock), sizeof sock);

  if (rv != 0 && errno != EISCONN && errno != 0) {
    g_log << Logger::Error << "Cannot connect to socket: " << strerror(errno) << std::endl;
    close(fd);
    connected = false;
    return;
  }
  // send initialize

  Json::array parameters;
  Json msg = Json(Json::object{
    {"method", "initialize"},
    {"parameters", Json(options)},
  });

  this->send(msg);
  msg = nullptr;
  if (this->recv(msg) == false) {
    g_log << Logger::Warning << "Failed to initialize backend" << std::endl;
    close(fd);
    this->connected = false;
  }
}
