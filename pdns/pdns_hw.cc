#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>

#include "namespaces.hh"
int main()
{
        ostringstream str;
        str << "Everything is ok!"<<"\n"; // FIXME400: boost test?
        exit(0);
}
