%{

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <utility>
#include <errno.h>
#include "misc.hh"
#include "pdnsexception.hh"
#include "namespaces.hh"
#define YYDEBUG 1
extern int yydebug;
#include "bindparserclasses.hh"

#define YYSTYPE char *

extern "C" 
{
	int yyparse(void);
	int yylex(void);
	void yyrestart(FILE *);
	int yywrap()
	{
		return 1;
	}
}


extern int yydebug;
const char *bind_directory;
extern int linenumber;
static void yyerror(const char *str)
{
  extern char *current_filename;	
  throw PDNSException("Error in bind configuration '"+string(current_filename)+"' on line "+itoa(linenumber)+": "+str);
}

extern FILE *yyin;
static BindParser *parent;
BindDomainInfo s_di;

void BindParser::parse(const string &fname)
{	
	yydebug=0;
	yyin=fopen(fname.c_str(),"r");
	yyrestart(yyin);
	if(!yyin)
		throw PDNSException("Unable to open '"+fname+"': "+strerror(errno));

	linenumber=1;
	parent=this;
	extern char *current_filename;
	extern char *original_filename;

	current_filename=original_filename=(char*)fname.c_str();

	yyparse();

//	cerr<<"Need to parse "<<d_zonedomains.size()<<" zone statements"<<endl;
}

void BindParser::setDirectory(const string &dir)
{
	d_dir=dir;
	bind_directory=d_dir.c_str();
}

void BindParser::addAlsoNotify(const string & host)
{
	alsoNotify.insert(host);
}

const string &BindParser::getDirectory()
{
	return d_dir;
}

const vector<BindDomainInfo>& BindParser::getDomains()
{
	return d_zonedomains;
}

void BindParser::setVerbose(bool verbose)
{
  d_verbose=verbose;
}

void BindParser::commit(BindDomainInfo DI)
{
  DI.hadFileDirective = (DI.filename != "");

  if(DI.filename[0]!='/')
    DI.filename=d_dir+"/"+DI.filename;

  if(d_verbose)
    cerr<<"Domain "<<DI.name.toStringNoDot()<<" lives in file '"<<DI.filename<<"'"<<endl;

  d_zonedomains.push_back(DI);
}

%}

/* Clause tokens */
%token ACLTOK
%token CONTROLTOK
%token DLZTOK
/*%token INCLUDETOK */	/* Handled by bindlexer.l */
%token KEYTOK
%token LOGGINGTOK
%token LWRESTOK
%token MANAGEDKEYSTOK
%token MASTERSTOK	/* Also a statement token */
%token OPTIONSTOK
%token SERVERTOK
%token STATISTICSCHANNELTOK
%token TRUSTEDKEYSTOK
%token VIEWTOK
%token ZONETOK

/* Statement block tokens */
%token ALSONOTIFYTOK
%token CHANNELTOK

/* Statement tokens */
%token DIRECTORYTOK
%token FILETOK
%token TYPETOK

/* Syntax tokens */
%token OBRACE EBRACE SEMICOLON

/* Generic tokens */
%token AWORD QUOTEDWORD

/**
Documented below are details about this grammar, including standards and
the nomenclature used.

GRAMMAR OVERVIEW

The grammar for a named.conf file consists of (what we shall call) "clauses",
which begin with a token, possibly followed by arguments, and definitely
followed by a block (defined using curly-braces, like C); clauses are then
terminated with a semicolon.  Contained in these blocks are zero or more
"statements", each of which may contain arguments or a block before being
terminated with a semicolon.  If a statement has a block, that block may
contain further statements (i.e. the grammar is nested).

For further details, see http://www.zytrax.com/books/dns/ch7/.

TERMINAL SYMBOLS

Symbols ending in "TOK" are tokens which match, or roughly match, a lowercase
string of the same name.  For example, "FILETOK" refers to a string literal of
"file" and "ALSONOTIFYTOK" refers to a string literal of "also-notify"; see
bindlexer.l.

Other tokens are for general syntax.  Notably, AWORD represents any word that
we do not explicitly have a token for (e.g. "update-policy" was not an explicit
token at the time of writing, as it was not used by PowerDNS).

NON-TERMINAL SYMBOLS

Generic Symbols

The generic symbols take no action when matched.  Their purpose is to handle
the tokens that aren't explicitly listed, i.e. the catch-all AWORD & QUOTEWORD
tokens.

These generic symbols CANNOT be used if a known token, i.e. a "*TOK" token,
might be encountered - nested within the blocks.  For example, the "logging"
clause can have a nested "file" statement.  While we don't care about the
contents of that "file" statement, we cannot use generic_block because we have
a FILETOK; an explicit rule must be written to handle that token.  See issue
#2290.

Specific symbols

Each nested statement (that is not a generic_statement) contains the parent in
its name, as a namespacing mechanism.  For example, see how statement 'y0' is
nested inside 'x0', which is itself nested in clause 'w':

+ w_clause
\-+ w_clause_statements
  \-+ w_clause_statement
    |-+ w_x0_statement
    | \-+ w_x0_block_statements
    |   \-+ w_x0_block_statement
    |     |-- w_x0_y0_statement
    |     \-- w_x0_y1_statement
    \-- w_x1_statement

NOTES

* The view clause can have nested clauses.
* If the optional arguments are known, they are listed in inline comments.

*/

%%

root: /* empty */
	|
	root clause SEMICOLON
	;

clause:
	acl_clause
	|
	controls_clause
	|
	dlz_clause
	/* |
	include_clause */	/* Handled by bindlexer.l */
	|
	key_clause
	|
	logging_clause
	|
	lwres_clause
	|
	managed_keys_clause
	|
	masters_clause
	|
	options_clause
	|
	server_clause
	|
	statistics_channel_clause
	|
	trusted_keys_clause
	|
	view_clause
	|
	zone_clause
	;

generic_statements: /* empty */
	|
	generic_statements generic_statement SEMICOLON
	;
generic_statement:
	generic_values
	|
	generic_values generic_block;

generic_block: OBRACE generic_statements EBRACE;

generic_values: /* empty */
	|
	generic_values generic_value
	;
generic_value: AWORD | quotedname;

quotedname: QUOTEDWORD
	{
		$$=$1;
	}
	;

acl_clause: ACLTOK quotedname generic_block;
controls_clause: CONTROLTOK generic_block;
dlz_clause: DLZTOK generic_values /* unknown */ generic_block;
key_clause: KEYTOK generic_values /* unknown */ generic_block;

logging_clause: LOGGINGTOK OBRACE logging_clause_statements EBRACE;
logging_clause_statements: /* empty */
	|
	logging_clause_statements logging_clause_statement SEMICOLON
	;
logging_clause_statement:
	generic_statement
	|
	logging_channel_statement
	;

logging_channel_statement: CHANNELTOK generic_value OBRACE logging_channel_block_statements EBRACE;
logging_channel_block_statements: /* empty */
	|
	logging_channel_block_statements logging_channel_block_statement SEMICOLON
	;
logging_channel_block_statement:
	generic_statement
	|
	logging_channel_file_statement
	;

logging_channel_file_statement: FILETOK quotedname generic_values /* [ "versions" ( <number> | "unlimited" ) ] [ "size" <size> ] */;

lwres_clause: LWRESTOK generic_values /* unknown */ generic_block;
managed_keys_clause: MANAGEDKEYSTOK generic_values /* unknown */ generic_block;
masters_clause: MASTERSTOK generic_value generic_values /* [ "port" <num> ] [ "dscp" <num> ] */ generic_block;

options_clause: OPTIONSTOK OBRACE options_clause_statements EBRACE;
options_clause_statements: /* empty */
	|
	options_clause_statements options_clause_statement SEMICOLON
	;
options_clause_statement:
	generic_statement
	|
	options_alsonotify_statement
	|
	options_directory_statement
	;

options_alsonotify_statement: ALSONOTIFYTOK generic_values /* [ "port" <num> ] [ "dscp" <num> ] */ OBRACE options_alsonotify_block_statements EBRACE;
options_alsonotify_block_statements: /* empty */
	|
	options_alsonotify_block_statements options_alsonotify_block_statement SEMICOLON
	;
options_alsonotify_block_statement: generic_value generic_values /* [ "port" <num> ] [ "dscp" <num> ] [ "key" <name> ] */
	{
		parent->addAlsoNotify($1);
		free($1);
	}
	;

options_directory_statement: DIRECTORYTOK quotedname
	{
		parent->setDirectory($2);
		free($2);
	}
	;

server_clause: SERVERTOK generic_value generic_block;
statistics_channel_clause: STATISTICSCHANNELTOK generic_values /* unknown */ generic_block;
trusted_keys_clause: TRUSTEDKEYSTOK generic_values /* unknown */ generic_block;

view_clause: view_clause_header OBRACE view_clause_statements EBRACE;
view_clause_header:
	VIEWTOK quotedname
	|
	VIEWTOK quotedname AWORD
	;
view_clause_statements: /* empty */
	|
	view_clause_statements view_clause_statement SEMICOLON
	;
view_clause_statement:
	generic_statement
	|
	key_clause
	|
	server_clause
	|
	trusted_keys_clause
	|
	zone_clause
	;

zone_clause:
	ZONETOK quotedname OBRACE zone_clause_statements EBRACE
	{
		s_di.name=DNSName($2);
		free($2);
		parent->commit(s_di);
		s_di.clear();
	}
	|
	ZONETOK quotedname AWORD OBRACE zone_clause_statements EBRACE
	{
		s_di.name=DNSName($2);
		free($2);
		parent->commit(s_di);
		s_di.clear();
	}
	;
zone_clause_statements: /* empty */
	|
	zone_clause_statements zone_clause_statement SEMICOLON
	;
zone_clause_statement:
	generic_statement
	|
	zone_alsonotify_statement
	|
	zone_file_statement
	|
	zone_masters_statement
	|
	zone_type_statement
	;

zone_alsonotify_statement: ALSONOTIFYTOK generic_values /* [ "port" <num> ] [ "dscp" <num> ] */ OBRACE zone_alsonotify_block_statements EBRACE;
zone_alsonotify_block_statements: /* empty */
	|
	zone_alsonotify_block_statements zone_alsonotify_block_statement SEMICOLON
	;
zone_alsonotify_block_statement: generic_value generic_values /* [ "port" <num> ] [ "dscp" <num> ] [ "key" <name> ] */
        {
                s_di.alsoNotify.insert($1);
                free($1);
        }
	;

zone_file_statement: FILETOK quotedname
	{
		s_di.filename=$2;
		free($2);
	}
	;

zone_masters_statement: MASTERSTOK generic_values /* [ "port" <num> ] [ "dscp" <num> ] */ OBRACE zone_masters_block_statements EBRACE;
zone_masters_block_statements: /* empty */
	|
	zone_masters_block_statements zone_masters_block_statement SEMICOLON
	;
zone_masters_block_statement: generic_value generic_values /* [ "port" <num> ] [ "dscp" <num> ] [ "key" <name> ] */
	{
		s_di.masters.push_back($1);
		free($1);
	}
	;

zone_type_statement: TYPETOK AWORD
	{
		s_di.type=$2;
		free($2);
	}
	;
