#pragma once

/*
 * C99 stdint.h implementation for Xbox XDK (Visual Studio 2003)
 * The Xbox XDK doesn't include this standard header.
 * Some types may already be defined by XDK headers, so we guard against redefinition.
 */

/* Exact-width integer types */
#ifndef _INT8_T_DEFINED
typedef signed char        int8_t;
#define _INT8_T_DEFINED
#endif

#ifndef _INT16_T_DEFINED
typedef short              int16_t;
#define _INT16_T_DEFINED
#endif

#ifndef _INT32_T_DEFINED
typedef long               int32_t;
#define _INT32_T_DEFINED
#endif

#ifndef _INT64_T_DEFINED
typedef long long          int64_t;
#define _INT64_T_DEFINED
#endif

#ifndef _UINT8_T_DEFINED
typedef unsigned char      uint8_t;
#define _UINT8_T_DEFINED
#endif

#ifndef _UINT16_T_DEFINED
typedef unsigned short     uint16_t;
#define _UINT16_T_DEFINED
#endif

#ifndef _UINT32_T_DEFINED
typedef unsigned long      uint32_t;
#define _UINT32_T_DEFINED
#endif

#ifndef _UINT64_T_DEFINED
typedef unsigned long long uint64_t;
#define _UINT64_T_DEFINED
#endif

/* Minimum-width integer types */
#ifndef _INT_LEAST8_T_DEFINED
typedef int8_t             int_least8_t;
typedef int16_t            int_least16_t;
typedef int32_t            int_least32_t;
typedef int64_t            int_least64_t;
typedef uint8_t            uint_least8_t;
typedef uint16_t           uint_least16_t;
typedef uint32_t           uint_least32_t;
typedef uint64_t           uint_least64_t;
#define _INT_LEAST8_T_DEFINED
#endif

/* Fastest minimum-width integer types */
#ifndef _INT_FAST8_T_DEFINED
typedef int32_t            int_fast8_t;
typedef int32_t            int_fast16_t;
typedef int32_t            int_fast32_t;
typedef int64_t            int_fast64_t;
typedef uint32_t           uint_fast8_t;
typedef uint32_t           uint_fast16_t;
typedef uint32_t           uint_fast32_t;
typedef uint64_t           uint_fast64_t;
#define _INT_FAST8_T_DEFINED
#endif

/* Integer types capable of holding object pointers */
#ifndef _INTPTR_T_DEFINED
typedef long               intptr_t;
#define _INTPTR_T_DEFINED
#endif

#ifndef _UINTPTR_T_DEFINED
typedef unsigned long      uintptr_t;
#define _UINTPTR_T_DEFINED
#endif

/* Greatest-width integer types */
#ifndef _INTMAX_T_DEFINED
typedef int64_t            intmax_t;
typedef uint64_t           uintmax_t;
#define _INTMAX_T_DEFINED
#endif

/* Signed integer type for size differences */
#ifndef _SSIZE_T_DEFINED
typedef long               ssize_t;
#define _SSIZE_T_DEFINED
#endif

/* Limits of exact-width integer types */
#ifndef INT8_MIN
#define INT8_MIN           (-128)
#endif
#ifndef INT8_MAX
#define INT8_MAX           127
#endif
#ifndef INT16_MIN
#define INT16_MIN          (-32768)
#endif
#ifndef INT16_MAX
#define INT16_MAX          32767
#endif
#ifndef INT32_MIN
#define INT32_MIN          (-2147483647L - 1)
#endif
#ifndef INT32_MAX
#define INT32_MAX          2147483647L
#endif
#ifndef INT64_MIN
#define INT64_MIN          (-9223372036854775807LL - 1)
#endif
#ifndef INT64_MAX
#define INT64_MAX          9223372036854775807LL
#endif

#ifndef UINT8_MAX
#define UINT8_MAX          255
#endif
#ifndef UINT16_MAX
#define UINT16_MAX         65535
#endif
#ifndef UINT32_MAX
#define UINT32_MAX         4294967295UL
#endif
#ifndef UINT64_MAX
#define UINT64_MAX         18446744073709551615ULL
#endif

/* Limits of minimum-width integer types */
#ifndef INT_LEAST8_MIN
#define INT_LEAST8_MIN     INT8_MIN
#define INT_LEAST8_MAX     INT8_MAX
#define INT_LEAST16_MIN    INT16_MIN
#define INT_LEAST16_MAX    INT16_MAX
#define INT_LEAST32_MIN    INT32_MIN
#define INT_LEAST32_MAX    INT32_MAX
#define INT_LEAST64_MIN    INT64_MIN
#define INT_LEAST64_MAX    INT64_MAX
#define UINT_LEAST8_MAX    UINT8_MAX
#define UINT_LEAST16_MAX   UINT16_MAX
#define UINT_LEAST32_MAX   UINT32_MAX
#define UINT_LEAST64_MAX   UINT64_MAX
#endif

/* Limits of fastest minimum-width integer types */
#ifndef INT_FAST8_MIN
#define INT_FAST8_MIN      INT32_MIN
#define INT_FAST8_MAX      INT32_MAX
#define INT_FAST16_MIN     INT32_MIN
#define INT_FAST16_MAX     INT32_MAX
#define INT_FAST32_MIN     INT32_MIN
#define INT_FAST32_MAX     INT32_MAX
#define INT_FAST64_MIN     INT64_MIN
#define INT_FAST64_MAX     INT64_MAX
#define UINT_FAST8_MAX     UINT32_MAX
#define UINT_FAST16_MAX    UINT32_MAX
#define UINT_FAST32_MAX    UINT32_MAX
#define UINT_FAST64_MAX    UINT64_MAX
#endif

/* Limits of integer types capable of holding object pointers */
#ifndef INTPTR_MIN
#define INTPTR_MIN         INT32_MIN
#endif
#ifndef INTPTR_MAX
#define INTPTR_MAX         INT32_MAX
#endif
#ifndef UINTPTR_MAX
#define UINTPTR_MAX        UINT32_MAX
#endif

/* Limits of greatest-width integer types */
#ifndef INTMAX_MIN
#define INTMAX_MIN         INT64_MIN
#endif
#ifndef INTMAX_MAX
#define INTMAX_MAX         INT64_MAX
#endif
#ifndef UINTMAX_MAX
#define UINTMAX_MAX        UINT64_MAX
#endif

/* Limits of other integer types */
#ifndef SIZE_MAX
#define SIZE_MAX           UINT32_MAX
#endif
#ifndef SSIZE_MAX
#define SSIZE_MAX          INT32_MAX
#endif

/* Macros for integer constant expressions */
#ifndef INT8_C
#define INT8_C(x)          (x)
#define INT16_C(x)         (x)
#define INT32_C(x)         (x ## L)
#define INT64_C(x)         (x ## LL)
#define UINT8_C(x)         (x)
#define UINT16_C(x)        (x)
#define UINT32_C(x)        (x ## UL)
#define UINT64_C(x)        (x ## ULL)
#define INTMAX_C(x)        INT64_C(x)
#define UINTMAX_C(x)       UINT64_C(x)
#endif 