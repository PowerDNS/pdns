/* A Bison parser, made by GNU Bison 1.875d.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     AWORD = 258,
     QUOTEDWORD = 259,
     OBRACE = 260,
     EBRACE = 261,
     SEMICOLON = 262,
     ZONETOK = 263,
     FILETOK = 264,
     OPTIONSTOK = 265,
     DIRECTORYTOK = 266,
     ACLTOK = 267,
     LOGGINGTOK = 268,
     CLASSTOK = 269,
     TYPETOK = 270,
     MASTERTOK = 271
   };
#endif
#define AWORD 258
#define QUOTEDWORD 259
#define OBRACE 260
#define EBRACE 261
#define SEMICOLON 262
#define ZONETOK 263
#define FILETOK 264
#define OPTIONSTOK 265
#define DIRECTORYTOK 266
#define ACLTOK 267
#define LOGGINGTOK 268
#define CLASSTOK 269
#define TYPETOK 270
#define MASTERTOK 271




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
typedef int YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;



