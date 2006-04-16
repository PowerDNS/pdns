#include <boost/function.hpp>
#include <boost/any.hpp>
#include <map>
#include <stdexcept>
#include <string>

class FDMultiplexerException : public std::runtime_error
{
public:
  FDMultiplexerException(const std::string& str) : std::runtime_error(str)
  {}
};

class FDMultiplexer
{
protected:
  typedef boost::function< void(int, boost::any&) > callbackfunc_t;
  struct Callback
  {
    callbackfunc_t d_callback;
    boost::any d_parameter;
  };

public:
  FDMultiplexer() : d_inrun(false)
  {}
  virtual ~FDMultiplexer()
  {}

  virtual int run(struct timeval* tv=0) = 0;

  virtual void addReadFD(int fd, callbackfunc_t toDo, boost::any parameter=boost::any())
  {
    this->addFD(d_inrun ? d_newReadCallbacks : d_readCallbacks, fd, toDo, parameter);
  }

  virtual void addWriteFD(int fd, callbackfunc_t toDo, boost::any parameter=boost::any())
  {
    this->addFD(d_inrun ? d_newWriteCallbacks : d_writeCallbacks, fd, toDo, parameter);
  }

  virtual void removeReadFD(int fd)
  {
    this->removeFD(d_inrun ? d_newReadCallbacks : d_readCallbacks, fd);
  }
  virtual void removeWriteFD(int fd)
  {
    this->removeFD(d_inrun ? d_newWriteCallbacks : d_writeCallbacks, fd);
  }

  virtual boost::any& getReadParameter(int fd) 
  {
    return d_readCallbacks[fd].d_parameter;
  }

protected:
  typedef std::map<int, Callback> callbackmap_t;
  callbackmap_t d_readCallbacks, d_writeCallbacks;
  callbackmap_t d_newReadCallbacks, d_newWriteCallbacks;

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, boost::any parameter)=0;
  virtual void removeFD(callbackmap_t& cbmap, int fd)=0;
  bool d_inrun;

};

class SelectFDMultiplexer : public FDMultiplexer
{
public:
  SelectFDMultiplexer()
  {}
  virtual ~SelectFDMultiplexer()
  {}

  virtual int run(struct timeval* tv=0);

  virtual void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, boost::any parameter);
  virtual void removeFD(callbackmap_t& cbmap, int fd);

private:
};

