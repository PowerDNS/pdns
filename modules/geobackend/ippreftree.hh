/*	ippreftree.hh
 * 	Copyright (C) 2004 Mark Bergsma <mark@nedworks.org>
 *		This software is licensed under the terms of the GPL, version 2.
 * 
 * 	$Id: ippreftree.hh,v 1.1 2004/02/28 19:13:44 ahu Exp $
 */

#include <string>
#include <sys/types.h>
#include <cstdlib>

using namespace std;

// Use old style C structs for efficiency
typedef struct node_t {
	node_t *child[2];
	short value;
} node_t;	

class IPPrefTree{

public:
	IPPrefTree();
	~IPPrefTree();

	void add(const string &prefix, const short value);	
	void add(const u_int32_t ip, const int preflen, const short value);
	
	short lookup(const string &prefix) const;
	short lookup(const u_int32_t ip, const int preflen) const;
	
	void clear();
	
	int getNodeCount() const;
	int getMemoryUsage() const;

private:
	node_t *root;	// root of the tree
	int nodecount;	// total number of nodes in the tree
	
	void addNode(node_t * node, const u_int32_t ip, const u_int32_t mask, const short value);
	node_t * allocateNode();
	const node_t * IPPrefTree::findDeepestFilledNode(const node_t *root, const u_int32_t ip, const u_int32_t mask) const;
	void removeNode(node_t * node);
	
	inline u_int32_t preflenToNetmask(const int preflen) const;
	inline void parsePrefix(const string &prefix, u_int32_t &ip, int &preflen) const;
};

class ParsePrefixException
{
public:
	ParsePrefixException() { reason = ""; };
	ParsePrefixException(string r) { reason = r; };
	
	string reason;
};
