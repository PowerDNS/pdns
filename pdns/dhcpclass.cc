#include "dhcpmessage.hh"
#include <stdlib.h>
#include <string.h>
#include "statbag.hh"
#include <iostream>

StatBag S;

int main(int argc, char** argv)
{
  DHCPCommunicator dc("10.0.0.11");
  cerr<<"Mac address of '"<<argv[1]<<"': "<<dc.getMac(argv[1])<<endl;
}
