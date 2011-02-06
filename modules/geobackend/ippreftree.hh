/*        ippreftree.hh
 *         Copyright (C) 2004 Mark Bergsma <mark@nedworks.org>
 *        	This software is licensed under the terms of the GPL, version 2.
 * 
 *         $Id$
 */

#include <string>
#include <sys/types.h>
#include <cstdlib>
#include <stdint.h>

#include "namespaces.hh"

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
        void add(const uint32_t ip, const int preflen, const short value);
        
        short lookup(const string &prefix) const;
        short lookup(const uint32_t ip, const int preflen) const;
        
        void clear();
        
        int getNodeCount() const;
        int getMemoryUsage() const;

private:
        node_t *root;	// root of the tree
        int nodecount;	// total number of nodes in the tree
        
        void addNode(node_t * node, const uint32_t ip, const uint32_t mask, const short value);
        node_t * allocateNode();
        const node_t * findDeepestFilledNode(const node_t *root, const uint32_t ip, const uint32_t mask) const;
        void removeNode(node_t * node);
        
        inline uint32_t preflenToNetmask(const int preflen) const;
        inline void parsePrefix(const string &prefix, uint32_t &ip, int &preflen) const;
};

class ParsePrefixException
{
public:
        ParsePrefixException() { reason = ""; };
        ParsePrefixException(string r) { reason = r; };
        
        string reason;
};
