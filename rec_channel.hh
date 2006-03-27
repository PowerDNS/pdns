#ifndef PDNS_REC_CHANNEL
#define PDNS_REC_CHANNEL
#include <string>
#include <map>
#include <stdint.h>
#include <sys/un.h>


/** this class is used both to send and answer channel commands to the PowerDNS Recursor */
class RecursorControlChannel
{
public:
  RecursorControlChannel() 
  {
    d_fd=-1;
    *d_local.sun_path=0;
  }

  ~RecursorControlChannel() 
  {
    if(d_fd > 0)
      close(d_fd);
    if(d_local.sun_path)
      unlink(d_local.sun_path);
  }


  int listen(const std::string& filename);
  void connect(const std::string& path, const std::string& filename);

  uint64_t getStat(const std::string& name);

  void send(const std::string& msg, const std::string* remote=0);
  std::string recv(std::string* remote=0);

  int d_fd;
private:
  struct sockaddr_un d_local;
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
