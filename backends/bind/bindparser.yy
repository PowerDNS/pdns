%{

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <utility>
#include <errno.h>
#include "misc.hh"
#include "ahuexception.hh"
using namespace std;
#define YYDEBUG 1
extern int yydebug;
#include "bindparser.hh"

#define YYSTYPE char *


#ifndef WIN32
extern "C" 
{
#endif // WIN32
	int yyparse(void);
	int yylex(void);
	void yyrestart(FILE *);
	int yywrap()
	{
		return 1;
	}
#ifndef WIN32
}
#endif // WIN32


extern int yydebug;
const char *bind_directory;
extern int linenumber;
static void yyerror(const char *str)
{
  extern char *current_filename;	
  throw AhuException("Error in bind configuration '"+string(current_filename)+"' on line "+itoa(linenumber)+": "+str);
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
		throw AhuException("Unable to open '"+fname+"': "+strerror(errno));

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
  if(DI.filename[0]!='/')
    DI.filename=d_dir+"/"+DI.filename;

  if(d_verbose)
    cerr<<"Domain "<<DI.name<<" lives in file '"<<DI.filename<<"'"<<endl;

  d_zonedomains.push_back(DI);
}

%}

%token AWORD QUOTEDWORD OBRACE EBRACE SEMICOLON ZONETOK FILETOK OPTIONSTOK
%token DIRECTORYTOK ACLTOK LOGGINGTOK CLASSTOK TYPETOK MASTERTOK

%%

root_commands:
	|	 
	root_commands root_command SEMICOLON
  	;

root_command: command | acl_command | zone_command | options_command
	;

commands:
	|
	commands command SEMICOLON
	;

command:
	terms 
	;

zone_command:
	ZONETOK quotedname zone_block
	{
		s_di.name=stripDot($2);
		free($2);
		
		parent->commit(s_di);
		s_di.clear();
	}
	|	
	ZONETOK quotedname AWORD zone_block
	{
	        s_di.name=$2;
		free($2);
		parent->commit(s_di);
		s_di.clear();
	}
	;


options_command:
	OPTIONSTOK OBRACE options_commands EBRACE
	|
	LOGGINGTOK OBRACE options_commands EBRACE
	;

acl_command:
	ACLTOK quotedname acl_block | 	ACLTOK filename acl_block
	;

acl_block: OBRACE acls EBRACE
	;
	
acls: 
	|
	acl SEMICOLON acls
	;

acl:
	AWORD
	;

options_commands:
	|
	options_command SEMICOLON options_commands
	;

options_command: command | options_directory_command
	;

options_directory_command: DIRECTORYTOK quotedname
	{
		parent->setDirectory($2);
		free($2);
	}
	;


terms: /* empty */
	|
	terms term
	;

term: AWORD | block | quotedname
	;
block: 
	OBRACE commands EBRACE 
	;

zone_block:
	OBRACE zone_commands EBRACE
	;

zone_commands:	
	|
	zone_commands zone_command SEMICOLON
	;

zone_command: command | zone_file_command | zone_type_command | zone_masters_command
	;

zone_masters_command: MASTERTOK OBRACE masters EBRACE
	;

masters: /* empty */
	| 
	masters master SEMICOLON 
	;

master: AWORD
	{
		s_di.master=$1;
		free($1);
	}
	;

zone_file_command:
	FILETOK quotedname
	{
	  //		printf("Found a filename: '%s'\n",$2);
		s_di.filename=$2;
		free($2);
	}
	;

zone_type_command:
TYPETOK AWORD
	{
		s_di.type=$2;
		free($2);
	}
	;


quotedname:
	QUOTEDWORD
	{
		$$=$1;
	}
	;

filename: AWORD
	;