/*
 * backendutil.cc
 *
 *  Created on: 11-May-2015
 *      Author: sumit_kumar
 */
#include <iostream>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <map>
#include <vector>
#include "pdns/qtype.hh"
#include "backendrecord.h"
#include "cassandratables.h"

#include "pdns/utility.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include <signal.h>
#include "pdns/arguments.hh"
#include "pdns/base32.hh"
#include "pdns/lock.hh"

typedef std::map<std::string, std::string>::iterator it_type_string_string;
typedef std::map<std::string, records>::iterator it_type_string_record;
typedef std::map<std::string, std::uint32_t>::iterator it_type_string_uint32_t;

class backendutil {
public:
	static vector<backendrecord> parse(domainlookuprecords* result) {
		int size = 0;
		if(result != NULL) {
			std::map<std::string, records> records_list = result->recordTypeResultArrayMap;
			for(it_type_string_record iterator = records_list.begin(); iterator != records_list.end(); iterator++) {
				records record = iterator->second;
				size+=record.recordMap.size();
			}
		}
		result->size = size;
		vector<backendrecord> output;
		string record_data;
		QType qtype;
		string type;
		if(result != NULL) {
			std::map<std::string, records> records_list = result->recordTypeResultArrayMap;
			for(it_type_string_record iterator = records_list.begin(); iterator != records_list.end(); iterator++) {
				type = iterator->first;
				records record = iterator->second;
				std::map<std::string,std::uint32_t> detailed_map = record.recordMap;
				for(it_type_string_uint32_t iterator_value = detailed_map.begin(); iterator_value != detailed_map.end(); iterator_value++) {
					record_data = iterator_value->first;
					backendrecord temp_output;
					temp_output.setRecord(record_data);
					qtype = type;
					temp_output.setType(qtype);
					temp_output.setTtl(detailed_map[record_data]);
					output.push_back(temp_output);
				}

			}
		}
		return output;
	}
};




