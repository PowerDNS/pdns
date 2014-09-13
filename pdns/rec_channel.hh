#ifndef PDNS_REC_CHANNEL
#define PDNS_REC_CHANNEL
#include <string>
#include <map>
#include <inttypes.h>
#include <sys/un.h>
#include <pthread.h>


/** this class is used both to send and answer channel commands to the PowerDNS Recursor */
class RecursorControlChannel
{
public:
  RecursorControlChannel();

  ~RecursorControlChannel();

  int listen(const std::string& filename);
  void connect(const std::string& path, const std::string& filename);

  uint64_t getStat(const std::string& name);

  void send(const std::string& msg, const std::string* remote=0);
  std::string recv(std::string* remote=0, unsigned int timeout=5);

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
private:
  static bool s_init;
};

std::map<std::string, std::string> getAllStatsMap();
extern pthread_mutex_t g_carbon_config_lock;
#endif 
