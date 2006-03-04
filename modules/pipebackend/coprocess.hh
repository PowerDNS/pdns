#ifndef PDNS_COPROCESS_HH
#define PDNS_COPROCESS_HH

#include <iostream>
#include <stdio.h>
#include <string>

using namespace std; 

class CoProcess
{
public:
  CoProcess(const string &command,int timeout=0, int infd=0, int outfd=1);
  CoProcess(const char **argv, int timeout=0, int infd=0, int outfd=1);
  ~CoProcess();

  void launch(const char **argv, int timeout=0, int infd=0, int outfd=1);
  void sendReceive(const string &send, string &receive);
  void receive(string &rcv);
  void send(const string &send);
private:
  void checkStatus();
  int d_fd1[2], d_fd2[2];
  int d_pid;
  int d_infd;
  int d_outfd;
  int d_timeout;
  FILE *d_fp;
};
#endif
