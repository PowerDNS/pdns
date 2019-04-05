/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"

uint64_t dnsdist_ffi_stat_node_get_queries_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->self.queries;
}

uint64_t dnsdist_ffi_stat_node_get_noerrors_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->self.noerrors;
}

uint64_t dnsdist_ffi_stat_node_get_nxdomains_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->self.nxdomains;
}

uint64_t dnsdist_ffi_stat_node_get_servfails_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->self.servfails;
}

uint64_t dnsdist_ffi_stat_node_get_drops_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->self.drops;
}

unsigned int dnsdist_ffi_stat_node_get_labels_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->node.labelsCount;
}

void dnsdist_ffi_stat_node_get_full_name_raw(const dnsdist_ffi_stat_node_t* node, const char** name, size_t* nameSize)
{
  const auto& storage = node->node.fullname;
  *name = storage.c_str();
  *nameSize = storage.size();
}

unsigned int dnsdist_ffi_stat_node_get_children_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->node.children.size();
}

uint64_t dnsdist_ffi_stat_node_get_children_queries_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->children.queries;
}

uint64_t dnsdist_ffi_stat_node_get_children_noerrors_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->children.noerrors;
}

uint64_t dnsdist_ffi_stat_node_get_children_nxdomains_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->children.nxdomains;
}

uint64_t dnsdist_ffi_stat_node_get_children_servfails_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->children.servfails;
}

uint64_t dnsdist_ffi_stat_node_get_children_drops_count(const dnsdist_ffi_stat_node_t* node)
{
  return node->children.drops;
}
