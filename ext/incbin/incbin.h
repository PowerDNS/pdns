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
# define INCBIN_ALIGNMENT_INDEX 4
#elif defined(__AVX__)
# define INCBIN_ALIGNMENT_INDEX 5
#else
# if ULONG_MAX == 0xffffffffu
#  define INCBIN_ALIGNMENT_INDEX 2
# else
#  define INCBIN_ALIGNMENT_INDEX 3
# endif
#endif

/* Lookup table of (1 << n) where `n' is `INCBIN_ALIGNMENT_INDEX' */
#define INCBIN_ALIGN_SHIFT_0 1
#define INCBIN_ALIGN_SHIFT_1 2
#define INCBIN_ALIGN_SHIFT_2 4
#define INCBIN_ALIGN_SHIFT_3 8
#define INCBIN_ALIGN_SHIFT_4 16
#define INCBIN_ALIGN_SHIFT_5 32

/* Common preprocessor utilities */
#define INCBIN_STR(X) #X
#define INCBIN_STRINGIZE(X) INCBIN_STR(X)

#define INCBIN_CAT(X, Y) X ## Y
#define INCBIN_CONCATENATE(X, Y) INCBIN_CAT(X, Y)

#define INCBIN_ALIGNMENT \
    INCBIN_CONCATENATE(INCBIN_ALIGN_SHIFT_, INCBIN_ALIGNMENT_INDEX)

/* Green Hills uses a different directive for including binary data */
#if defined(__ghs__)
#  define INCBIN_MACRO "\tINCBIN"
#else
#  define INCBIN_MACRO ".incbin"
#endif

#ifndef _MSC_VER
#  define INCBIN_ALIGN \
    __attribute__((aligned(INCBIN_ALIGNMENT)))
#else
#  define INCBIN_ALIGN __declspec(align(INCBIN_ALIGNMENT))
#endif

#if defined(__arm__) || /* GNU C and RealView */ \
    defined(__arm) || /* Diab */ \
    defined(_ARM) /* ImageCraft */
#  define INCBIN_ARM
#endif

#ifdef __GNUC__
/* Utilize .balign where supported */
#  define INCBIN_ALIGN_HOST ".balign " INCBIN_STRINGIZE(INCBIN_ALIGNMENT) "\n"
#  define INCBIN_ALIGN_BYTE ".balign 1\n"
#elif defined(INCBIN_ARM)
/*
 * On arm assemblers, the alignment value is calculated as (1 << n) where `n' is
 * the shift count. This is the value passed to `.align'
 */
#  define INCBIN_ALIGN_HOST ".align" INCBIN_STRINGIZE(INCBIN_ALIGNMENT_INDEX) "\n"
#  define INCBIN_ALIGN_BYTE ".align 0\n"
#else
/* We assume other inline assembler's treat `.align' as `.balign' */
#  define INCBIN_ALIGN_HOST ".align" INCBIN_STRINGIZE(INCBIN_ALIGNMENT) "\n"
#  define INCBIN_ALIGN_BYTE ".align 1\n"
#endif

/* INCBIN_CONST is used by incbin.c generated files */
#if defined(__cplusplus)
#  define INCBIN_EXTERNAL extern "C"
#  define INCBIN_CONST    extern const
#else
#  define INCBIN_EXTERNAL extern
#  define INCBIN_CONST    const
#endif

#if defined(__APPLE__)
/* The directives are different for Apple branded compilers */
#  define INCBIN_SECTION         ".const_data\n"
#  define INCBIN_GLOBAL(NAME)    ".globl " INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME "\n"
#  define INCBIN_INT             ".long "
#  define INCBIN_MANGLE          "_"
#  define INCBIN_BYTE            ".byte"
#  define INCBIN_TYPE(...)
#else
#  define INCBIN_SECTION         ".section .rodata\n"
#  define INCBIN_GLOBAL(NAME)    ".global " INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME "\n"
#  define INCBIN_INT             ".int "
#  if defined(__USER_LABEL_PREFIX__)
#    define INCBIN_MANGLE        INCBIN_STRINGIZE(__USER_LABEL_PREFIX__)
#  else
#    define INCBIN_MANGLE        ""
#  endif
#  if defined(INCBIN_ARM)
/* On arm assemblers, `@' is used as a line comment token */
#    define INCBIN_TYPE(NAME)    ".type " INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME ", %object\n"
#  else
/* It's safe to use `@' on other architectures */
#    define INCBIN_TYPE(NAME)    ".type " INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME ", @object\n"
#  endif
#  define INCBIN_BYTE            ".byte "
#endif

/**
 * @breif Specify the prefix to use for symbol names.
 *
 * By default this is `g', producing symbols of the form:
 * @code
 * #include "incbin.h"
 * INCBIN(Foo, "foo.txt");
 *
 * // Now you have the following symbols:
 * // const unsigned char gFooData[];
 * // const unsigned char *gFooEnd;
 * // const unsigned int gFooSize;
 * @endcode
 *
 * If however you specify a prefix before including: e.g:
 * @code
 * #define INCBIN_PREFIX incbin
 * #include "incbin.h"
 * INCBIN(Foo, "foo.txt");
 *
 * // Now you have the following symbols instead:
 * // const unsigned char incbinFooData[];
 * // const unsigned char *incbinFooEnd;
 * // const unsigned int incbinFooSize;
 * @endcode
 */
#if !defined(INCBIN_PREFIX)
#  define INCBIN_PREFIX g
#endif

/**
 * @brief Externally reference binary data included in another translation unit.
 *
 * Produces three external symbols that reference the binary data included in
 * another translation unit.
 *
 * The symbol names are a concatenation of `INCBIN_PREFIX' before *NAME*; with
 * "Data", as well as "End" and "Size" after. An example is provided below.
 *
 * @param NAME The name given for the binary data
 *
 * @code
 * INCBIN_EXTERN(Foo);
 *
 * // Now you have the following symbols:
 * // extern const unsigned char <prefix>FooData[];
 * // extern const unsigned char *<prefix>FooEnd;
 * // extern const unsigned int <prefix>FooSize;
 * @endcode
 */
#define INCBIN_EXTERN(NAME) \
    INCBIN_EXTERNAL const INCBIN_ALIGN unsigned char INCBIN_CONCATENATE(INCBIN_PREFIX, NAME ## Data)[]; \
    INCBIN_EXTERNAL const INCBIN_ALIGN unsigned char *INCBIN_CONCATENATE(INCBIN_PREFIX, NAME ## End); \
    INCBIN_EXTERNAL const unsigned int INCBIN_CONCATENATE(INCBIN_PREFIX, NAME ## Size)

/**
 * @brief Include a binary file into the current translation unit.
 *
 * Includes a binary file into the current translation unit, producing three symbols
 * for objects that encode the data and size respectively.
 *
 * The symbol names are a concatenation of `INCBIN_PREFIX' before *NAME*; with
 * "Data", as well as "End" and "Size" after. An example is provided below.
 *
 * @param NAME The name to associate with this binary data (as an identifier.)
 * @param FILENAME The file to include (as a string literal.)
 *
 * @code
 * INCBIN(Icon, "icon.png");
 *
 * // Now you have the following symbols:
 * // const unsigned char <prefix>IconData[];
 * // const unsigned char *<prefix>IconEnd;
 * // const unsigned int <prefix>IconSize;
 * @endcode
 *
 * @warning This must be used in global scope
 *
 * To externally reference the data included by this in another translation unit
 * please @see INCBIN_EXTERN.
 */
#ifdef _MSC_VER
#define INCBIN(NAME, FILENAME) \
    INCBIN_EXTERN(NAME)
#else
#define INCBIN(NAME, FILENAME) \
    __asm__(INCBIN_SECTION \
            INCBIN_GLOBAL(NAME ## Data) \
            INCBIN_TYPE(NAME ## Data) \
            INCBIN_ALIGN_HOST \
            INCBIN_MANGLE INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME "Data:\n" \
            INCBIN_MACRO " \"" FILENAME "\"\n" \
            INCBIN_GLOBAL(NAME ## End) \
            INCBIN_TYPE(NAME ## End) \
            INCBIN_ALIGN_BYTE \
            INCBIN_MANGLE INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME "End:\n" \
                INCBIN_BYTE "1\n" \
            INCBIN_GLOBAL(NAME ## Size) \
            INCBIN_TYPE(NAME ## Size) \
            INCBIN_ALIGN_HOST \
            INCBIN_MANGLE INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME "Size:\n" \
                INCBIN_INT INCBIN_MANGLE INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME "End - " \
                           INCBIN_MANGLE INCBIN_STRINGIZE(INCBIN_PREFIX) #NAME "Data\n" \
    ); \
    INCBIN_EXTERN(NAME)

#endif
#endif
