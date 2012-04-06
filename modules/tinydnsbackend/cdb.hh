#ifndef CDB_HH
#define CDB_HH

#include <pdns/logger.hh>
#include <cdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// This class is responsible for the reading of a CDB file.
// The constructor opens the CDB file, the destructor closes it, so make sure you call that.
class CDB
{
public:
	CDB(const string &cdbfile);
	~CDB();

	int searchKey(const string &key);
	bool searchSuffix(const string &key);
	void searchAll();
	bool readNext(pair<string, string> &value);
	vector<string> findall(string &key);

private:
	int d_fd;
	bool moveToNext();
	struct cdb d_cdb;
	struct cdb_find d_cdbf;
	char *d_key;
	unsigned d_seqPtr;
	enum SearchType { SearchSuffix, SearchKey, SearchAll } d_searchType;
};

#endif // CDB_HH 
