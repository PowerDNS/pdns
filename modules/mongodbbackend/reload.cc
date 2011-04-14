/*
    Copyright (C) 2011 Fredrik Danerklint

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published 
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "mongodbbackend.hh"

#include "pdns/logger.hh"
#include "pdns/arguments.hh"

/* 
    virtual void reload();
*/

void MONGODBBackend::reload() {
    logging = ::arg().mustDo("query-logging") || mustDo("logging-query");

    logging_cerr = mustDo("logging-cerr");
    logging_content = mustDo("logging-content");
    
    dnssec = mustDo("dnssec");
    checkindex = mustDo("checkindex");

    use_default_ttl = mustDo("use-default-ttl");
    
    backend_name.clear();

//    backend_name = "[MONGODBBackend: " + uitoa(backend_pid) + " (" + uitoa(backend_count) +")] ";
    backend_name = "[MONGODBBackend: (" + uitoa(backend_count) +")] ";
}
