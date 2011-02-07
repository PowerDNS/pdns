/*        ippreftree.cc
 *         Copyright (C) 2004 Mark Bergsma <mark@nedworks.org>
 *        	This software is licensed under the terms of the GPL, version 2.
 * 
 *         $Id$
 */

#include <sstream>

#include "ippreftree.hh"

IPPrefTree::IPPrefTree(): nodecount(0) {
        root = allocateNode();
        nodecount++;
}

IPPrefTree::~IPPrefTree() {
        removeNode(root);
}

void IPPrefTree::add(const string &prefix, const short value) {
        uint32_t ip;
        int preflen;
        parsePrefix(prefix, ip, preflen);
        
        add(ip, preflen, value);
}

void IPPrefTree::add(const uint32_t ip, const int preflen, const short value) {
        addNode(root, ip, preflenToNetmask(preflen), value);
}

short IPPrefTree::lookup(const string &prefix) const {
        uint32_t ip;
        int preflen;
        parsePrefix(prefix, ip, preflen);
        
        return lookup(ip, preflen);
}

short IPPrefTree::lookup(const uint32_t ip, const int preflen) const {
        const node_t *node = findDeepestFilledNode(root, ip, preflenToNetmask(preflen));
        return (node == NULL ? 0 : node->value);
}

void IPPrefTree::clear() {
        // Remove all children of the root node, but not the root node itself (reallocate it)
        removeNode(root);
        root = allocateNode();
        nodecount++;
}

int IPPrefTree::getNodeCount() const {
        return nodecount;
}

int IPPrefTree::getMemoryUsage() const {
        return nodecount * sizeof(node_t);
}

// Private methods

inline uint32_t IPPrefTree::preflenToNetmask (const int preflen) const {
        return ~( (1 << (32 - preflen)) - 1);
}

inline void IPPrefTree::parsePrefix(const string &prefix, uint32_t &ip, int &preflen) const {
        // Parse the prefix string (with format 131.155.230.139/25)
        std::istringstream is(prefix);
        ip = 0; preflen = 32;
        char c;
        
        for (int i = 0; i < 4; i++) {
        	int octet = 0;
        	is >> octet;
        	ip = (ip << 8) | octet;
        	is.get(c);
        	if (c != '.' && c != '/')
        		throw ParsePrefixException("Invalid format: expected '.' or '/'");
        }
        
        if (is.good() && c == '/') {
        	// Read the prefix length
        	is >> preflen;
        }	
}

void IPPrefTree::addNode(node_t *node, const uint32_t ip, const uint32_t mask, const short value) {
        if (mask == 0) {
        	// We are at the correct depth in the tree
        	node->value = value;
        }
        else {	/* mask > 0 */
        	// We need to walk deeper into the tree, and extend it if needed
        	int b = (ip >> 31);
        	
        	if (node->child[b] == NULL) {
        		node->child[b] = allocateNode();
        		nodecount++;
        	}
        	
        	// Recursively add
        	addNode(node->child[b], ip << 1, mask << 1, value);
        }
}

node_t * IPPrefTree::allocateNode() {
        node_t *node = new node_t;
        
        // Initialize
        node->child[0] = node->child[1] = NULL;
        node->value = 0;
        
        return node;	
}

const node_t * IPPrefTree::findDeepestFilledNode(const node_t *node, const uint32_t ip, const uint32_t mask) const {
        if (node == NULL) return NULL;
        
        if (mask == 0) {
        	return (node->value == 0 ? NULL : node);
        }
        else {	/* mask > 0 */
        	int b = (ip >> 31);
        	const node_t *descendant = findDeepestFilledNode(node->child[b], ip << 1, mask << 1);
        	if (descendant == NULL) {
        		if (node->value != 0)	// Children have no (more) explicit information, do we?
        			return node;
        		else
        			return NULL;
        	}
        	else
        		return descendant;
        }
}

void IPPrefTree::removeNode(node_t *node) {
        if (node == NULL) return;
        
        // Recursively remove and deallocate all descendants
        removeNode(node->child[0]);
        removeNode(node->child[1]);
        nodecount--;
        
        delete node;
}        
