/**
 * @file incbin.h
 * @author Dale Weiler
 * @brief Utility for including binary files
 *
 * Facilities for including binary files into the current translation unit and
 * making use from them externally in other translation units.
 */
#ifndef INCBIN_HDR
#define INCBIN_HDR
#include <limits.h>

#if defined(__SSE__) || defined(__neon__)
# define INCBIN_ALIGNMENT 16
#else
# if ULONG_MAX == 0xffffffffu
#  define INCBIN_ALIGNMENT 4
# else
#  define INCBIN_ALIGNMENT 8
# endif
#endif

#define INCBIN_ALIGN __attribute__((aligned(INCBIN_ALIGNMENT)))

#ifdef __cplusplus
#  define INCBIN_EXTERNAL extern "C"
#else
#  define INCBIN_EXTERNAL extern
#endif

#ifdef __APPLE__
#  define INCBIN_SECTION         ".const_data\n"
#  define INCBIN_GLOBAL(NAME)    ".globl " #NAME "\n"
#  define INCBIN_INT             ".long "
#  define INCBIN_MANGLE          "_"
#  define INCBIN_TYPE(...)
#else
#  define INCBIN_SECTION         ".section .rodata\n"
#  define INCBIN_GLOBAL(NAME)    ".global " #NAME "\n"
#  define INCBIN_INT             ".int "
#  define INCBIN_MANGLE
#  define INCBIN_TYPE(NAME)      ".type " #NAME ", @object\n"
#endif

#define INCBIN_STR(X) #X
#define INCBIN_STRINGIZE(X) INCBIN_STR(X)

/**
 * @brief Externally reference binary data included in another translation unit.
 *
 * Produces two external symbols that reference the binary data included in
 * another translation unit.
 *
 * The symbol names are a concatenation of "g" before *NAME*; with "Data", as well
 * as "Size" after. An example is provided below.
 *
 * @param NAME The name given for the binary data
 *
 * @code
 * INCBIN_EXTERN(Foo);
 *
 * // Now you have the following symbols:
 * // extern unsigned char gFooData[];
 * // extern const unsigned char gFooEnd;
 * // extern unsigned int gFooSize;
 * @endcode
 */
#define INCBIN_EXTERN(NAME) \
    INCBIN_EXTERNAL const INCBIN_ALIGN unsigned char g ## NAME ## Data[]; \
    INCBIN_EXTERNAL const INCBIN_ALIGN unsigned char g ## NAME ## End; \
    INCBIN_EXTERNAL const unsigned int g ## NAME ## Size

/**
 * @brief Include a binary file into the current translation unit.
 *
 * Includes a binary file into the current translation unit, producing two symbols
 * for objects that encode the data and size respectively.
 *
 * The symbol names are a concatenation of "g" before *NAME*; with "Data", as well
 * as "Size" after. An example is provided below.
 *
 * @param NAME The name to associate with this binary data (as an identifier.)
 * @param FILENAME The file to include (as a string literal.)
 *
 * @code
 * INCBIN(Icon, "icon.png");
 *
 * // Now you have the following symbols:
 * // unsigned char gIconData[];
 * // unsigned int gIconSize;
 * @endcode
 *
 * @warning This must be used in global scope
 *
 * To externally reference the data included by this in another translation unit
 * please @see INCBIN_EXTERN.
 */
#define INCBIN(NAME, FILENAME) \
    __asm__(INCBIN_SECTION \
            INCBIN_GLOBAL(g ## NAME ## Data) \
            INCBIN_TYPE(g ## NAME ## Data) \
            ".align " INCBIN_STRINGIZE(INCBIN_ALIGNMENT) "\n" \
            INCBIN_MANGLE "g" #NAME "Data:\n" \
                ".incbin \"" FILENAME "\"\n" \
            INCBIN_GLOBAL(g ## NAME ## End) \
            INCBIN_TYPE(g ## NAME ## End) \
            ".align 1\n" \
            INCBIN_MANGLE "g" #NAME "End:\n" \
                INCBIN_INT "1\n"\
            INCBIN_GLOBAL(g ## NAME ## Size) \
            INCBIN_TYPE(g ## NAME ## Size) \
            ".align " INCBIN_STRINGIZE(INCBIN_ALIGNMENT) "\n" \
            INCBIN_MANGLE "g" #NAME "Size:\n" \
                INCBIN_INT INCBIN_MANGLE "g" #NAME "End - " INCBIN_MANGLE "g" #NAME "Data\n" \
    ); \
    INCBIN_EXTERN(NAME)

#endif
