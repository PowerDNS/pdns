#ifndef BISON_Y_TAB_H
# define BISON_Y_TAB_H

# ifndef YYSTYPE
#  define YYSTYPE int
#  define YYSTYPE_IS_TRIVIAL 1
# endif
# define	WORD	257
# define	QUOTEDWORD	258
# define	OBRACE	259
# define	EBRACE	260
# define	SEMICOLON	261
# define	ZONETOK	262
# define	FILETOK	263
# define	OPTIONSTOK	264
# define	DIRECTORYTOK	265
# define	ACLTOK	266
# define	LOGGINGTOK	267
# define	CLASSTOK	268
# define	TYPETOK	269
# define	MASTERTOK	270


extern YYSTYPE yylval;

#endif /* not BISON_Y_TAB_H */
