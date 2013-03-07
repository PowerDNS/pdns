#ifndef PDNS_COPROCESS_HH
#define PDNS_COPROCESS_HH

#include <iostream>
#include <stdio.h>
#include <string>

#include "pdns/namespaces.hh"

class CoRemote
{
public:
  virtual void sendReceive(const string &send, string &receive) = 0;
  virtual void receive(string &rcv) = 0;
  virtual void send(const string &send) = 0;

};

class CoProcess : public CoRemote
{
public:
  CoProcess(const string &command,int timeout=0, int infd=0, int outfd=1);
  ~CoProcess();
  void sendReceive(const string &send, string &receive);
  void receive(string &rcv);
  void send(const string &send);
private:
  void launch(const char **argv, int timeout=0, int infd=0, int outfd=1);
  void checkStatus();
  int d_fd1[2], d_fd2[2];
  int d_pid;
  int d_infd;
  int d_outfd;
  int d_timeout;
  FILE *d_fp;
};

class UnixRemote : public CoRemote
{
public:
  UnixRemote(const string &path, int timeout=0);
  ~UnixRemote();
  void sendReceive(const string &send, string &receive);
  void receive(string &rcv);
  void send(const string &send);
private:
  int d_fd;
  FILE *d_fp;
};
bool isUnixSocket(const string& fname);
#endif
