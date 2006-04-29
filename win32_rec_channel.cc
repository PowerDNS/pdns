#include "rec_channel.hh"
#include <cerrno>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>

#include "ahuexception.hh"

using namespace std;

RecursorControlChannel::RecursorControlChannel()
{
}

RecursorControlChannel::~RecursorControlChannel() 
{
}

int RecursorControlChannel::listen(const string& fname)
{
  return 0;
}

void RecursorControlChannel::connect(const string& path, const string& fname)
{

}

void RecursorControlChannel::send(const std::string& msg, const std::string* remote)
{

}

string RecursorControlChannel::recv(std::string* remote)
{
  return 0;
}

