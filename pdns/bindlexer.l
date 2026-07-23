%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define YY_NO_INPUT 1
#define YYSTYPE char *

#include "bindparser.hh"

int linenumber;
#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int include_stack_ln[MAX_INCLUDE_DEPTH];
char *include_stack_name[MAX_INCLUDE_DEPTH];
char *current_filename;
char *original_filename;
int include_stack_ptr = 0;
extern const char *bind_directory;

/* This is the name mangling of BindParser::lexer_error */
#define LEXER_ERROR _ZN10BindParser11lexer_errorEPKcPci
extern void LEXER_ERROR(const char *, char *, int);

static void bindlexer_cleanup()
{
  /* be sure not to leave any file open */
  if (yyin != NULL) {
    fclose(yyin);
    yyin = NULL;
  }
}

static void bindlexer_fatal_error(const char* msg)
{
  bindlexer_cleanup();
  LEXER_ERROR(msg, NULL, 0);
}

#define YY_FATAL_ERROR bindlexer_fatal_error

%}

%x comment
%x incl
%x quoted
%option stack
%option nounput
%option noyy_top_state
%option noinput
%option nodefault

%%


"/*"         BEGIN(comment);
<comment>[^*\n]*        /* eat anything that's not a '*' */
<comment>"*"+[^*/\n]*   /* eat up '*'s not followed by '/'s */
<comment>\n             ++linenumber;
<comment>"*"+"/"        BEGIN(INITIAL);

include                 BEGIN(incl);
<incl>[ \t;]*            /* eat the whitespace */
<incl>\"[^ \t\n";]+\";        { /* got the include file name */
        char filename[1024];
        if ( include_stack_ptr >= MAX_INCLUDE_DEPTH )
            {
            YY_FATAL_ERROR( "Includes nested too deeply" );
            }

        if (strlen(yytext) <= 2) {
            YY_FATAL_ERROR( "Empty include directive" );
        }

        yytext[strlen(yytext)-2]=0;

        include_stack[include_stack_ptr]=YY_CURRENT_BUFFER;
        include_stack_name[include_stack_ptr]=current_filename=strdup(yytext+1);
        include_stack_ln[include_stack_ptr++]=linenumber;
        linenumber=1;

        int ret;
        if(*(yytext+1)=='/') {
            ret = snprintf(filename, sizeof(filename), "%s", yytext+1);
        }
        else {
            ret = snprintf(filename, sizeof(filename), "%s/%s", bind_directory, yytext+1);
        }
        if (ret == -1 || ret >= (int)sizeof(filename)) {
            bindlexer_cleanup();
            LEXER_ERROR( "name too long", yytext+1, 0);
        }

        if (!(yyin=fopen(filename,"r"))) {
          bindlexer_cleanup();
          LEXER_ERROR( "unable to open",filename,errno);
        }

        BEGIN(INITIAL);
        yy_switch_to_buffer(yy_create_buffer(yyin,YY_BUF_SIZE));

   }


<<EOF>>   {
        if ( --include_stack_ptr < 0 )
        {
            yyterminate();
        }

        else
            {
            fclose(yyin);
            yy_delete_buffer(YY_CURRENT_BUFFER);
            yy_switch_to_buffer(include_stack[include_stack_ptr]);
            linenumber=include_stack_ln[include_stack_ptr];
            free(include_stack_name[include_stack_ptr]);
            if(include_stack_ptr)
                 current_filename=include_stack_name[include_stack_ptr-1];
            else
                 current_filename=original_filename;
            }
        }




zone			return ZONETOK;

file			return FILETOK;
options                 return OPTIONSTOK;
also-notify		return ALSONOTIFYTOK;
acl                     return ACLTOK;
logging                 return LOGGINGTOK;
directory               return DIRECTORYTOK;
masters                 return PRIMARYTOK;
primaries               return PRIMARYTOK;
type                    return TYPETOK;
\"                      yy_push_state(quoted);
<quoted>[^\"]*          yylval=strdup(yytext); return QUOTEDWORD;
<quoted>\"              yy_pop_state();
[^\" \t\n{};]*               yylval=strdup(yytext);return AWORD;
\{                      return OBRACE;
\}                      return EBRACE;
;                       return SEMICOLON;
\n                      linenumber++;
[ \t]*                  ;
\/\/.*$			;
\#.*$			;
%%
