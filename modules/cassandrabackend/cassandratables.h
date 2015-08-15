/*
 * ultratables.h
 *
 *  Created on: 11-May-2015
 *      Author: sumit_kumar
 */
#include <string.h>
#include <map>
struct records {
	std::map<std::string,std::uint32_t> recordMap;
};
struct domainlookuprecords
{
public:
	const char* domain;
    std::map<std::string, records> recordTypeResultArrayMap;
    bool disabled;
    time_t creation_time;
    int32_t size;
    void clear() {
    	domain = NULL;
    	recordTypeResultArrayMap.clear();
    	disabled = false;
    	creation_time = NULL;
    	size = 0;
    }
};
