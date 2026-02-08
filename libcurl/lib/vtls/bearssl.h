#ifndef HEADER_CURL_BEARSSL_H
#define HEADER_CURL_BEARSSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * BearSSL TLS backend for libcurl
 * Designed for Xbox (Visual Studio 2003 / C89 compatible)
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_BEARSSL

extern const struct Curl_ssl Curl_ssl_bearssl;

#endif /* USE_BEARSSL */
#endif /* HEADER_CURL_BEARSSL_H */
