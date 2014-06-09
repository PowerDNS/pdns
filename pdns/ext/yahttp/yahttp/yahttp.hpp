#include <map>
#include <iostream>
#include <locale>
#include <algorithm>
#include <string>
#include <cstdio>
#include <sys/time.h>
#include <iomanip>
#include <list>
#include <vector>

#include "yahttp-config.h"
#include "url.hpp"
#include "utility.hpp"
#include "exception.hpp"
#include "url.hpp"
#include "cookie.hpp"
#include "reqresp.hpp"

/*! \mainpage Yet Another HTTP Library Documentation
\section sec_quick_start Quick start example

@code
#include <yahttp/yahttp.hpp>

int main(void) {
  std::ifstream ifs("request.txt");
  YaHTTP::Request req;
  ifs >> req;

  std::cout << req.method " " << req.url.path << std::endl;
  return 0;
}
@endcode
\author Aki Tuomi
*/
