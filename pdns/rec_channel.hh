#ifndef PDNS_REC_CHANNEL
#define PDNS_REC_CHANNEL
#include <string>
#include <map>
#include <stdint.h>

/** this class is used both to send and answer channel commands to the PowerDNS Recursor */
class RecursorControlChannel
{
public:
  int listen(const std::string& filename);
  void connect(const std::string& path, const std::string& filename);

  uint64_t getStat(const std::string& name);

  void send(const std::string& msg, const std::string* remote=0);
  std::string recv(std::string* remote=0);

  int d_fd;
};

class RecursorControlParser
{
public:
  RecursorControlParser();
  static void nop(void){}
  typedef void func_t(void);
  std::string getAnswer(const std::string& question, func_t** func);

};


#endif 
