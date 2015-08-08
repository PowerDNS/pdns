#include <iostream>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <map>
#include "pdns/qtype.hh"
#include "backendrecord.h"
#include "cassandratables.h"
typedef std::map<std::string, std::string>::iterator it_type;

class backendutil {
public:
	static backendrecord* parse(domainlookuprecords* result) {
		int size = 0;
		if(result != NULL) {
			std::map<std::string, records> records_list = result->recordTypeResultArrayMap;
			for(it_type iterator = records_list.begin(); iterator != records_list.end(); iterator++) {
				records record = iterator->second;
				size+=record.recordMap.size();
			}
		}
		result->size = size;
		backendrecord* output = new backendrecord[size];
		int i = 0;
		if(result != NULL) {
			std::map<std::string, records> records_list = result->recordTypeResultArrayMap;
			for(it_type iterator = records_list.begin(); iterator != records_list.end(); iterator++) {
				std:string type = iterator->first;
				records record = iterator->second;
				std::map<std::string,std::uint32_t> detailed_map = record.recordMap;
				for(it_type iterator_value = detailed_map.begin(); iterator_value != detailed_map.end(); iterator_value++) {
					std:string record_data = iterator_value->first;
					output[i].setRecord(record_data);
					QType qtype = type;
					output[i].setType(qtype.types);
					output[i].setTtl(detailed_map[record_data]);
					i++;
				}

			}
		}
		return output;
	}
};




