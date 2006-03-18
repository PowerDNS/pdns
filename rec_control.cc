#include "rec_channel.hh"
#include <iostream>
#include "ahuexception.hh"

using namespace std;

int main(int argc, char** argv)
try
{
  RecursorControlChannel rccS;
  rccS.connect("pdns_recursor.controlsocket");

  string command;
  for(int i=1; i< argc; ++i) {
    if(i>1)
      command+=" ";
    command+=argv[i];
  }


  rccS.send(command);

  string receive=rccS.recv();
  
  cout<<receive;
}
catch(AhuException& ae)
{
  cerr<<"Fatal: "<<ae.reason<<"\n";
}
