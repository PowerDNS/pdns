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
#ifndef PDNS_COPROCESS_HH
#define PDNS_COPROCESS_HH

#include <iostream>
#include <stdio.h>
#include <string>

#include "pdns/namespaces.hh"

class CoRemote
{
public:
  virtual ~CoRemote() {}
  virtual void sendReceive(const string &send, string &receive) = 0;
  virtual void receive(string &rcv) = 0;
  virtual void send(const string &send) = 0;

};

class CoProcess : public CoRemote
{
public:
  CoProcess(const string &command,int timeout=0, int infd=0, int outfd=1);
  ~CoProcess();
  void sendReceive(const string &send, string &receive) override;
  void receive(string &rcv) override;
  void send(const string &send) override;
  void launch();
private:
  void checkStatus();
  std::vector<std::string> d_params;
  std::vector<const char *> d_argv;
  std::string d_remaining;
  int d_fd1[2], d_fd2[2];
  int d_pid;
  int d_infd;
  int d_outfd;
  int d_timeout;
};

class UnixRemote : public CoRemote
{
public:
  UnixRemote(const string &path, int timeout=0);
  ~UnixRemote();
  void sendReceive(const string &send, string &receive) override;
  void receive(string &rcv) override;
  void send(const string &send) override;
private:
  int d_fd;
  FILE *d_fp;
};
bool isUnixSocket(const string& fname);
#endif
