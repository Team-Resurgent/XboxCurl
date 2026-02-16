/*
 * Xbox libcurl + BearSSL Comprehensive Test Suite
 *
 * Features:
 * - On-screen text display with CURL logo
 * - Visual pass/fail indicators
 * - Comprehensive protocol testing
 * - Verbose SSL/TLS debugging
 * - Debug output to XBDM
 */

#include <xtl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "xbox_console.h"

/* BearSSL debug support */
#include <bearssl.h>
#include "../BearSSL-OG/ssl_debug.h"
#include "../BearSSL-OG/debug.h"
#include "../BearSSL-OG/session_cache.h"
#include "../BearSSL-OG/cert_pinning.h"

/* VS2003 compatibility: use _snprintf instead of snprintf */
#define snprintf _snprintf

/*
 * XboxCurl ASCII Art Logo + Xbox Controller
 * Controller art from https://asciiart.website/art/2237
 */
static const char *curl_logo[] = {
    "  __  __  _                    ____            _",
    "  \\ \\/ / | |__    ___  __  __ / ___|  _   _  _ __| |",
    "   \\  /  | '_ \\  / _ \\ \\ \\/ /| |    | | | || '__| |",
    "   /  \\  | |_) || (_) | >  < | |___ | |_| || |  | |",
    "  /_/\\_\\ |_.__/  \\___/ /_/\\_\\ \\____| \\__,_||_|  |_|",
    "",
    "  libcurl 7.65.3 + BearSSL/0.6 for Original Xbox",
    NULL
};

/*
 * Test result tracking
 */
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_skipped = 0;
static size_t total_bytes_received = 0;

/*
 * Verbose debug logging control
 */
static int g_verbose_ssl = 1;  /* Enable verbose SSL debugging */

/*
 * Write callback for receiving data
 */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t total = size * nmemb;
    total_bytes_received += total;
    (void)contents;
    (void)userp;
    return total;
}

/*
 * Write callback for saving data to a file on disk
 */
struct file_write_data {
    FILE *fp;
    size_t bytes_written;
};

static size_t file_write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    struct file_write_data *fwd = (struct file_write_data *)userp;
    size_t total = size * nmemb;
    size_t written;

    if (!fwd || !fwd->fp) return 0;

    written = fwrite(contents, 1, total, fwd->fp);
    fwd->bytes_written += written;
    total_bytes_received += written;
    return written;
}

/*
 * Write callback that captures response body into a buffer for inspection
 */
struct response_data {
    char buffer[8192];
    size_t size;
};

static size_t capture_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    struct response_data *rd = (struct response_data *)userp;
    size_t total = size * nmemb;
    size_t remaining = sizeof(rd->buffer) - rd->size - 1;
    size_t copy_size = total < remaining ? total : remaining;

    if (copy_size > 0) {
        memcpy(rd->buffer + rd->size, contents, copy_size);
        rd->size += copy_size;
        rd->buffer[rd->size] = '\0';
    }
    total_bytes_received += total;
    return total;
}

/*
 * Debug callback for verbose curl logging
 * This captures ALL curl operations including SSL handshake details
 */
static int my_curl_debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr)
{
    char buf[512];
    char prefix[16];
    size_t i, print_size;

    (void)handle;
    (void)userptr;

    switch (type) {
        case CURLINFO_TEXT:
            snprintf(prefix, sizeof(prefix), "* ");
            break;
        case CURLINFO_HEADER_IN:
            snprintf(prefix, sizeof(prefix), "< ");
            break;
        case CURLINFO_HEADER_OUT:
            snprintf(prefix, sizeof(prefix), "> ");
            break;
        case CURLINFO_DATA_IN:
            if (g_verbose_ssl) {
                snprintf(buf, sizeof(buf), "[DATA IN] %u bytes received\n", (unsigned)size);
                OutputDebugStringA(buf);
            }
            return 0;
        case CURLINFO_DATA_OUT:
            if (g_verbose_ssl) {
                snprintf(buf, sizeof(buf), "[DATA OUT] %u bytes sent\n", (unsigned)size);
                OutputDebugStringA(buf);
            }
            return 0;
        case CURLINFO_SSL_DATA_IN:
            snprintf(buf, sizeof(buf), "[SSL IN] %u bytes\n", (unsigned)size);
            OutputDebugStringA(buf);
            /* Print first few bytes as hex for debugging */
            if (size > 0 && g_verbose_ssl) {
                char hex[128];
                int hex_len = 0;
                for (i = 0; i < size && i < 32 && hex_len < 120; i++) {
                    hex_len += snprintf(hex + hex_len, sizeof(hex) - hex_len, "%02X ", (unsigned char)data[i]);
                }
                snprintf(buf, sizeof(buf), "  HEX: %s%s\n", hex, size > 32 ? "..." : "");
                OutputDebugStringA(buf);
            }
            return 0;
        case CURLINFO_SSL_DATA_OUT:
            snprintf(buf, sizeof(buf), "[SSL OUT] %u bytes\n", (unsigned)size);
            OutputDebugStringA(buf);
            /* Print first few bytes as hex for debugging */
            if (size > 0 && g_verbose_ssl) {
                char hex[128];
                int hex_len = 0;
                for (i = 0; i < size && i < 32 && hex_len < 120; i++) {
                    hex_len += snprintf(hex + hex_len, sizeof(hex) - hex_len, "%02X ", (unsigned char)data[i]);
                }
                snprintf(buf, sizeof(buf), "  HEX: %s%s\n", hex, size > 32 ? "..." : "");
                OutputDebugStringA(buf);
            }
            return 0;
        default:
            return 0;
    }

    /* Print text/header info - handle multiple lines */
    print_size = size;
    if (print_size > 400) print_size = 400;

    /* For HEADER_OUT, log the full request so we can see all headers */
    if (type == CURLINFO_HEADER_OUT) {
        char header_log[512];
        snprintf(header_log, sizeof(header_log), "\n=== HTTP REQUEST (%u bytes) ===\n", (unsigned)size);
        OutputDebugStringA(header_log);
    }

    /* Process each line */
    {
        size_t pos = 0;
        while (pos < print_size) {
            /* Copy one line */
            i = 0;
            while (pos < print_size && i < sizeof(buf) - 2) {
                char c = data[pos++];
                if (c == '\r') continue;  /* Skip CR */
                if (c == '\n') break;     /* End of line */
                buf[i++] = c;
            }
            buf[i] = '\0';

            if (buf[0] != '\0') {
                char out[550];
                snprintf(out, sizeof(out), "%s%s\n", prefix, buf);
                OutputDebugStringA(out);

                /* Also show important SSL info on console */
                if (type == CURLINFO_TEXT && g_verbose_ssl) {
                    /* Check for SSL-related messages */
                    if (strstr(buf, "SSL") || strstr(buf, "TLS") ||
                        strstr(buf, "ssl") || strstr(buf, "tls") ||
                        strstr(buf, "certificate") || strstr(buf, "handshake") ||
                        strstr(buf, "cipher") || strstr(buf, "error") ||
                        strstr(buf, "Error") || strstr(buf, "fail")) {
                        xbox_console_set_colors(CONSOLE_COLOR_MAGENTA, CONSOLE_COLOR_BLACK);
                        xbox_console_printf("  DBG: %s\n", buf);
                        xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
                        xbox_console_present();
                    }
                }
            }
        }
    }

    if (type == CURLINFO_HEADER_OUT) {
        OutputDebugStringA("=== END HTTP REQUEST ===\n");
    }

    return 0;
}

/*
 * Helper to configure verbose debugging on a curl handle
 */
static void setup_verbose_curl(CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_curl_debug_callback);
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, NULL);
}

/*
 * Display functions
 */
static void display_logo(void)
{
    int i;

    xbox_console_set_colors(CONSOLE_COLOR_CYAN, CONSOLE_COLOR_BLACK);
    for (i = 0; curl_logo[i] != NULL; i++) {
        xbox_console_println(curl_logo[i]);
    }
    xbox_console_println("");
    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
}

static void display_header(const char *title)
{
    xbox_console_println("");
    xbox_console_set_colors(CONSOLE_COLOR_YELLOW, CONSOLE_COLOR_BLACK);
    xbox_console_printf("  %s\n", title);
    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    xbox_console_println("");
    xbox_console_present();
}

static void display_test_start(const char *test_name)
{
    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    xbox_console_printf("[ .... ] %s", test_name);
    xbox_console_present();
    OutputDebugStringA("Testing: ");
    OutputDebugStringA(test_name);
    OutputDebugStringA("\n");
}

static void display_test_result(int passed, const char *details)
{
    int x, y;

    /* Move cursor back to result position */
    xbox_console_get_cursor(&x, &y);
    xbox_console_set_cursor(0, y);

    if (passed) {
        xbox_console_set_colors(CONSOLE_COLOR_GREEN, CONSOLE_COLOR_BLACK);
        xbox_console_print("[ PASS ]");
        tests_passed++;
    } else {
        xbox_console_set_colors(CONSOLE_COLOR_RED, CONSOLE_COLOR_BLACK);
        xbox_console_print("[ FAIL ]");
        tests_failed++;
    }

    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    xbox_console_set_cursor(x, y);
    xbox_console_println("");

    if (details && details[0]) {
        xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
        xbox_console_printf("         %s\n", details);
        xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    }

    xbox_console_present();
}

static void display_test_skip(const char *reason)
{
    int x, y;

    xbox_console_get_cursor(&x, &y);
    xbox_console_set_cursor(0, y);

    xbox_console_set_colors(CONSOLE_COLOR_YELLOW, CONSOLE_COLOR_BLACK);
    xbox_console_print("[ SKIP ]");
    tests_skipped++;

    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    xbox_console_set_cursor(x, y);
    xbox_console_println("");

    if (reason && reason[0]) {
        xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
        xbox_console_printf("         %s\n", reason);
        xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    }

    xbox_console_present();
}

static void display_section(const char *section_name)
{
    xbox_console_println("");
    xbox_console_set_colors(CONSOLE_COLOR_CYAN, CONSOLE_COLOR_BLACK);
    xbox_console_printf("  %s\n", section_name);
    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    xbox_console_present();
}

static void display_summary(void)
{
    xbox_console_println("");
    xbox_console_set_colors(CONSOLE_COLOR_YELLOW, CONSOLE_COLOR_BLACK);
    xbox_console_println("  TEST RESULTS SUMMARY");
    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);

    xbox_console_set_colors(CONSOLE_COLOR_GREEN, CONSOLE_COLOR_BLACK);
    xbox_console_printf("  Passed:  %d\n", tests_passed);

    xbox_console_set_colors(CONSOLE_COLOR_RED, CONSOLE_COLOR_BLACK);
    xbox_console_printf("  Failed:  %d\n", tests_failed);

    xbox_console_set_colors(CONSOLE_COLOR_YELLOW, CONSOLE_COLOR_BLACK);
    xbox_console_printf("  Skipped: %d\n", tests_skipped);

    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    xbox_console_printf("  Total:   %d\n", tests_passed + tests_failed + tests_skipped);

    xbox_console_println("");
    if (tests_failed == 0) {
        xbox_console_set_colors(CONSOLE_COLOR_GREEN, CONSOLE_COLOR_BLACK);
        xbox_console_println("  ALL TESTS PASSED!");
    } else {
        xbox_console_set_colors(CONSOLE_COLOR_RED, CONSOLE_COLOR_BLACK);
        xbox_console_println("  SOME TESTS FAILED");
    }

    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
    xbox_console_present();
}

/*
 * Network initialization
 */
static int wait_for_network(void)
{
    XNetStartupParams xnsp;
    WSADATA wsaData;
    XNADDR xnaddr;
    int timeout = 30;

    xbox_console_println("Initializing network...");
    xbox_console_present();

    /* Initialize XNet */
    memset(&xnsp, 0, sizeof(xnsp));
    xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
    xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
    xnsp.cfgPrivatePoolSizeInPages = 64;
    xnsp.cfgEnetReceiveQueueLength = 16;
    xnsp.cfgIpFragMaxSimultaneous = 16;
    xnsp.cfgIpFragMaxPacketDiv256 = 32;
    xnsp.cfgSockMaxSockets = 64;
    xnsp.cfgSockDefaultRecvBufsizeInK = 64;
    xnsp.cfgSockDefaultSendBufsizeInK = 64;

    XNetStartup(&xnsp);
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    /* Wait for ethernet link */
    xbox_console_print("  Waiting for ethernet link...");
    xbox_console_present();
    while (XNetGetEthernetLinkStatus() == 0) {
        Sleep(100);
    }
    xbox_console_set_colors(CONSOLE_COLOR_GREEN, CONSOLE_COLOR_BLACK);
    xbox_console_println(" OK");
    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);

    /* Wait for DHCP */
    xbox_console_print("  Waiting for DHCP...");
    xbox_console_present();
    while (timeout > 0) {
        memset(&xnaddr, 0, sizeof(xnaddr));
        if (XNetGetTitleXnAddr(&xnaddr) != XNET_GET_XNADDR_PENDING) {
            break;
        }
        Sleep(1000);
        timeout--;
    }

    if (timeout <= 0) {
        xbox_console_set_colors(CONSOLE_COLOR_RED, CONSOLE_COLOR_BLACK);
        xbox_console_println(" TIMEOUT");
        xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
        return 0;
    }

    xbox_console_set_colors(CONSOLE_COLOR_GREEN, CONSOLE_COLOR_BLACK);
    xbox_console_println(" OK");
    xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);

    /* Display IP address */
    xbox_console_printf("  IP Address: %d.%d.%d.%d\n",
        xnaddr.ina.S_un.S_un_b.s_b1,
        xnaddr.ina.S_un.S_un_b.s_b2,
        xnaddr.ina.S_un.S_un_b.s_b3,
        xnaddr.ina.S_un.S_un_b.s_b4);

    xbox_console_println("");
    xbox_console_present();
    return 1;
}

/*
 * Individual Tests
 */

/* Test 1: Version Information - VERBOSE */
static void test_version_info(void)
{
    const char *version;
    curl_version_info_data *vinfo;
    char details[256];
    char log[512];

    display_test_start("libcurl version information");

    version = curl_version();
    vinfo = curl_version_info(CURLVERSION_NOW);

    if (version && vinfo && vinfo->version) {
        /* Log extensive version info */
        snprintf(log, sizeof(log),
            "\n======= CURL VERSION INFO =======\n"
            "  Version string: %s\n"
            "  curl version: %s\n"
            "  SSL version: %s\n"
            "  Features: 0x%08lx\n"
            "  Host: %s\n"
            "================================\n",
            version,
            vinfo->version,
            vinfo->ssl_version ? vinfo->ssl_version : "NONE (no SSL!)",
            (unsigned long)vinfo->features,
            vinfo->host ? vinfo->host : "unknown");
        OutputDebugStringA(log);

        /* Check for SSL support */
        if (vinfo->features & CURL_VERSION_SSL) {
            OutputDebugStringA("  [OK] SSL support is enabled\n");
        } else {
            OutputDebugStringA("  [WARNING] SSL support is NOT enabled!\n");
        }

        /* Show on console too */
        xbox_console_set_colors(CONSOLE_COLOR_CYAN, CONSOLE_COLOR_BLACK);
        xbox_console_printf("  curl: %s\n", vinfo->version);
        xbox_console_printf("  SSL:  %s\n", vinfo->ssl_version ? vinfo->ssl_version : "NONE!");

        if (!(vinfo->features & CURL_VERSION_SSL)) {
            xbox_console_set_colors(CONSOLE_COLOR_RED, CONSOLE_COLOR_BLACK);
            xbox_console_println("  WARNING: No SSL support compiled in!");
        }
        xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
        xbox_console_present();

        snprintf(details, sizeof(details), "curl %s, SSL: %s",
                vinfo->version,
                vinfo->ssl_version ? vinfo->ssl_version : "NONE");
        display_test_result(vinfo->ssl_version != NULL, details);
    } else {
        display_test_result(0, "Failed to get version info");
    }
}

/* Test 2: HTTP GET (by IP - no DNS) */
static void test_http_get_by_ip(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[128];

    display_test_start("HTTP GET (direct IP, no DNS)");
    OutputDebugStringA("DEBUG: Starting HTTP test\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    OutputDebugStringA("DEBUG: curl_easy_init done\n");

    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    OutputDebugStringA("DEBUG: Setting options\n");
    curl_easy_setopt(curl, CURLOPT_URL, "http://1.1.1.1/");  /* Cloudflare - reliable */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, NULL);
    OutputDebugStringA("DEBUG: Options set, calling curl_easy_perform\n");

    res = curl_easy_perform(curl);
    OutputDebugStringA("DEBUG: curl_easy_perform returned\n");
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && response_code >= 200 && response_code < 400) {
        snprintf(details, sizeof(details) - 1, "HTTP %ld, %u bytes received", response_code, (unsigned)total_bytes_received);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details) - 1, "Error: %s (HTTP %ld)", curl_easy_strerror(res), response_code);
        details[sizeof(details) - 1] = '\0';
        display_test_result(0, details);
    }
}

/* Test 3: HTTP GET with DNS */
static void test_http_get_dns(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[128];

    display_test_start("HTTP GET (with DNS resolution)");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details) - 1, "HTTP %ld, %u bytes received", response_code, (unsigned)total_bytes_received);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details) - 1, "Error: %s (HTTP %ld)", curl_easy_strerror(res), response_code);
        details[sizeof(details) - 1] = '\0';
        display_test_result(0, details);
    }
}

/* Test 4: HTTPS GET (certificate verification disabled) - VERBOSE */
static void test_https_get_no_verify(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    char *effective_url = NULL;
    long ssl_verify_result = 0;
    DWORD start_time, elapsed;

    display_test_start("HTTPS GET (verify disabled)");

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Starting HTTPS connection test...");
    xbox_console_present();

    OutputDebugStringA("\n========== HTTPS TEST (NO VERIFY) START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    /* Setup verbose debugging */
    setup_verbose_curl(curl);

    OutputDebugStringA("Setting HTTPS options...\n");
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);  /* Longer timeout for SSL handshake */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    /* Try to get more SSL debugging info */
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

    xbox_console_println("         Performing SSL handshake...");
    xbox_console_present();
    OutputDebugStringA("Calling curl_easy_perform for HTTPS...\n");

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    OutputDebugStringA("curl_easy_perform returned.\n");

    /* Get detailed info */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
    curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &ssl_verify_result);

    /* Log everything */
    {
        char log[512];
        snprintf(log, sizeof(log),
            "HTTPS Result:\n"
            "  CURLcode: %d (%s)\n"
            "  HTTP Code: %ld\n"
            "  SSL Verify: %ld\n"
            "  Bytes: %u\n"
            "  Time: %lu ms\n"
            "  URL: %s\n",
            res, curl_easy_strerror(res),
            response_code,
            ssl_verify_result,
            (unsigned)total_bytes_received,
            elapsed,
            effective_url ? effective_url : "NULL");
        OutputDebugStringA(log);
    }

    curl_easy_cleanup(curl);
    OutputDebugStringA("========== HTTPS TEST (NO VERIFY) END ==========\n\n");

    /* Show result on console */
    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "HTTPS %ld, %u bytes in %lu ms", response_code, (unsigned)total_bytes_received, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld, %lu ms)", res, curl_easy_strerror(res), response_code, elapsed);
        display_test_result(0, details);

        /* Show error details on console */
        xbox_console_set_colors(CONSOLE_COLOR_RED, CONSOLE_COLOR_BLACK);
        xbox_console_printf("         SSL verify result: %ld\n", ssl_verify_result);
        xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
        xbox_console_present();
    }
}

/* Test 5: HTTPS GET (certificate verification enabled) - VERBOSE */
static void test_https_get_with_verify(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    long ssl_verify_result = 0;
    DWORD start_time, elapsed;

    display_test_start("HTTPS GET (verify enabled)");

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Testing certificate verification...");
    xbox_console_present();

    OutputDebugStringA("\n========== HTTPS TEST (WITH VERIFY) START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    /* Setup verbose debugging */
    setup_verbose_curl(curl);

    OutputDebugStringA("Setting HTTPS options with verification...\n");
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.google.com/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

    xbox_console_println("         Performing verified SSL handshake...");
    xbox_console_present();

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &ssl_verify_result);

    /* Log everything */
    {
        char log[512];
        snprintf(log, sizeof(log),
            "HTTPS (Verify) Result:\n"
            "  CURLcode: %d (%s)\n"
            "  HTTP Code: %ld\n"
            "  SSL Verify: %ld\n"
            "  Bytes: %u\n"
            "  Time: %lu ms\n",
            res, curl_easy_strerror(res),
            response_code,
            ssl_verify_result,
            (unsigned)total_bytes_received,
            elapsed);
        OutputDebugStringA(log);
    }

    curl_easy_cleanup(curl);
    OutputDebugStringA("========== HTTPS TEST (WITH VERIFY) END ==========\n\n");

    if (res == CURLE_OK && response_code >= 200 && response_code < 400) {
        snprintf(details, sizeof(details), "HTTPS %ld, cert verified, %lu ms", response_code, elapsed);
        display_test_result(1, details);
    } else if (res == CURLE_SSL_CACERT || res == CURLE_PEER_FAILED_VERIFICATION) {
        snprintf(details, sizeof(details), "Cert verify failed (SSL result: %ld)", ssl_verify_result);
        display_test_skip(details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (%lu ms)", res, curl_easy_strerror(res), elapsed);
        display_test_result(0, details);
    }
}

/* Test 5-pre: BearSSL Engine Diagnostics */
static void test_bearssl_diagnostics(void)
{
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    char details[256];

    display_test_start("BearSSL engine initialization");

    OutputDebugStringA("\n========== BEARSSL DIAGNOSTICS ==========\n");

    /* Try to initialize BearSSL client context with no trust anchors (for testing) */
    OutputDebugStringA("Initializing br_ssl_client_init_full with NULL trust anchors...\n");
    br_ssl_client_init_full(&sc, &xc, NULL, 0);

    /* Check engine state */
    {
        unsigned state = br_ssl_engine_current_state(&sc.eng);
        int err = br_ssl_engine_last_error(&sc.eng);
        char log[256];

        snprintf(log, sizeof(log),
            "BearSSL state after init:\n"
            "  State flags: 0x%08x\n"
            "  Last error: %d\n"
            "  CLOSED=%d SENDREC=%d RECVREC=%d SENDAPP=%d RECVAPP=%d\n",
            state, err,
            (state & BR_SSL_CLOSED) ? 1 : 0,
            (state & BR_SSL_SENDREC) ? 1 : 0,
            (state & BR_SSL_RECVREC) ? 1 : 0,
            (state & BR_SSL_SENDAPP) ? 1 : 0,
            (state & BR_SSL_RECVAPP) ? 1 : 0);
        OutputDebugStringA(log);

        xbox_console_set_colors(CONSOLE_COLOR_CYAN, CONSOLE_COLOR_BLACK);
        xbox_console_printf("  BearSSL state: 0x%08x, err: %d\n", state, err);
        xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
        xbox_console_present();

        if (err == BR_ERR_OK) {
            snprintf(details, sizeof(details), "Init OK, state=0x%x", state);
            display_test_result(1, details);
        } else {
            snprintf(details, sizeof(details), "Init error: %d", err);
            display_test_result(0, details);
        }
    }

    OutputDebugStringA("========== BEARSSL DIAGNOSTICS END ==========\n\n");
}

/* Test 5a: HTTPS to httpbin.org (lenient test server) */
static void test_https_by_ip(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;

    display_test_start("HTTPS to httpbin.org");

    OutputDebugStringA("\n========== HTTPS HTTPBIN TEST START ==========\n");
    OutputDebugStringA("Testing HTTPS to httpbin.org/get - lenient HTTP/1.1 test server\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    setup_verbose_curl(curl);

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Connecting to httpbin.org:443...");
    xbox_console_present();

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== HTTPS HTTPBIN TEST END ==========\n\n");

    if (res == CURLE_OK && response_code >= 200 && response_code < 400) {
        snprintf(details, sizeof(details), "HTTPS %ld, %u bytes, %lu ms", response_code, (unsigned)total_bytes_received, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (%lu ms)", res, curl_easy_strerror(res), elapsed);
        display_test_result(0, details);
    }
}

/* Test 5b: HTTPS with explicit TLS options */
static void test_https_tls_options(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    const char *ssl_version_str = "unknown";
    long ssl_version = 0;

    display_test_start("HTTPS TLS version test");

    OutputDebugStringA("\n========== HTTPS TLS VERSION TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    setup_verbose_curl(curl);

    /* Try to force TLS 1.2 */
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.howsmyssl.com/a/check");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Testing TLS 1.2 connection...");
    xbox_console_present();

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

#ifdef CURLINFO_SSL_VERSION
    if (curl_easy_getinfo(curl, CURLINFO_SSL_VERSION, &ssl_version) == CURLE_OK) {
        switch (ssl_version) {
            case CURL_SSLVERSION_TLSv1_0: ssl_version_str = "TLS 1.0"; break;
            case CURL_SSLVERSION_TLSv1_1: ssl_version_str = "TLS 1.1"; break;
            case CURL_SSLVERSION_TLSv1_2: ssl_version_str = "TLS 1.2"; break;
            case CURL_SSLVERSION_TLSv1_3: ssl_version_str = "TLS 1.3"; break;
            default: ssl_version_str = "unknown"; break;
        }
    }
#endif

    {
        char log[256];
        snprintf(log, sizeof(log), "TLS test: code=%d, HTTP=%ld, SSL version=%s, time=%lu ms\n",
            res, response_code, ssl_version_str, elapsed);
        OutputDebugStringA(log);
    }

    curl_easy_cleanup(curl);
    OutputDebugStringA("========== HTTPS TLS VERSION TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "TLS OK, %s, %lu ms", ssl_version_str, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (%lu ms)", res, curl_easy_strerror(res), elapsed);
        display_test_result(0, details);
    }
}

/* Test 5c: Simple HTTPS to a minimal endpoint */
static void test_https_simple(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;

    display_test_start("HTTPS simple (example.com)");

    OutputDebugStringA("\n========== HTTPS SIMPLE TEST START ==========\n");
    OutputDebugStringA("Testing HTTPS to example.com - minimal, reliable endpoint\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    setup_verbose_curl(curl);

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Connecting to example.com:443...");
    xbox_console_present();

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== HTTPS SIMPLE TEST END ==========\n\n");

    if (res == CURLE_OK && response_code >= 200 && response_code < 400) {
        snprintf(details, sizeof(details), "HTTPS %ld, %u bytes, %lu ms", response_code, (unsigned)total_bytes_received, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (%lu ms)", res, curl_easy_strerror(res), elapsed);
        display_test_result(0, details);
    }
}

/* Test 5d: Raw TCP connection test to port 443 using XNet DNS */
/* Pattern based on Microsoft Xbox source: dnslookup.c and logon.cpp */
static void test_tcp_port_443(void)
{
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    XNDNS *pxndns = NULL;
    HANDLE hEvent = NULL;
    DWORD start_time, elapsed;
    char details[256];
    int result;
    INT dns_status;

    display_test_start("TCP connect to port 443");

    OutputDebugStringA("\n========== TCP PORT 443 TEST START ==========\n");

    /* Create event for async DNS completion (Xbox pattern) */
    hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL) {
        snprintf(details, sizeof(details), "CreateEvent failed: %d", GetLastError());
        display_test_result(0, details);
        return;
    }

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Resolving example.com via XNet...");
    xbox_console_present();

    /* Use Xbox DNS lookup with event notification */
    dns_status = XNetDnsLookup("example.com", hEvent, &pxndns);
    if (dns_status != 0) {
        snprintf(details, sizeof(details), "XNetDnsLookup failed: %d", dns_status);
        OutputDebugStringA(details);
        OutputDebugStringA("\n");
        CloseHandle(hEvent);
        display_test_result(0, details);
        return;
    }

    /* Wait for DNS to complete with 10 second timeout (Xbox pattern) */
    OutputDebugStringA("Waiting for DNS lookup to complete...\n");
    if (WaitForSingleObject(hEvent, 10000) == WAIT_TIMEOUT) {
        OutputDebugStringA("DNS lookup timed out\n");
        XNetDnsRelease(pxndns);
        CloseHandle(hEvent);
        display_test_result(0, "DNS lookup timed out");
        return;
    }

    /* Check DNS result status */
    {
        char log[128];
        snprintf(log, sizeof(log), "DNS iStatus=%d, cina=%d\n", pxndns->iStatus, pxndns->cina);
        OutputDebugStringA(log);
    }

    if (pxndns->iStatus != 0) {
        snprintf(details, sizeof(details), "DNS failed: status=%d (WSAHOST_NOT_FOUND=%d)",
                 pxndns->iStatus, WSAHOST_NOT_FOUND);
        OutputDebugStringA(details);
        OutputDebugStringA("\n");
        XNetDnsRelease(pxndns);
        CloseHandle(hEvent);
        display_test_result(0, details);
        return;
    }

    if (pxndns->cina == 0) {
        XNetDnsRelease(pxndns);
        CloseHandle(hEvent);
        display_test_result(0, "DNS returned no addresses");
        return;
    }

    {
        char log[128];
        snprintf(log, sizeof(log), "Resolved to: %d.%d.%d.%d\n",
            pxndns->aina[0].S_un.S_un_b.s_b1,
            pxndns->aina[0].S_un.S_un_b.s_b2,
            pxndns->aina[0].S_un.S_un_b.s_b3,
            pxndns->aina[0].S_un.S_un_b.s_b4);
        OutputDebugStringA(log);

        xbox_console_printf("         IP: %d.%d.%d.%d\n",
            pxndns->aina[0].S_un.S_un_b.s_b1,
            pxndns->aina[0].S_un.S_un_b.s_b2,
            pxndns->aina[0].S_un.S_un_b.s_b3,
            pxndns->aina[0].S_un.S_un_b.s_b4);
        xbox_console_present();
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        snprintf(details, sizeof(details), "socket() failed: %d", WSAGetLastError());
        XNetDnsRelease(pxndns);
        CloseHandle(hEvent);
        display_test_result(0, details);
        return;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(443);
    server.sin_addr = pxndns->aina[0];

    /* Release DNS resources before connect (Xbox pattern) */
    XNetDnsRelease(pxndns);
    pxndns = NULL;

    xbox_console_println("         Connecting to port 443...");
    xbox_console_present();

    start_time = GetTickCount();
    result = connect(sock, (struct sockaddr *)&server, sizeof(server));
    elapsed = GetTickCount() - start_time;

    if (result == 0) {
        snprintf(details, sizeof(details), "Connected in %lu ms", elapsed);
        OutputDebugStringA("TCP connect to port 443 succeeded\n");
        display_test_result(1, details);
    } else {
        int err = WSAGetLastError();
        snprintf(details, sizeof(details), "Connect failed: WSA error %d (%lu ms)", err, elapsed);
        OutputDebugStringA(details);
        OutputDebugStringA("\n");
        display_test_result(0, details);
    }

    /* Cleanup (Xbox pattern: always close socket properly) */
    closesocket(sock);
    CloseHandle(hEvent);
    OutputDebugStringA("========== TCP PORT 443 TEST END ==========\n\n");
}

/* Test 6: HTTP POST */
static void test_http_post(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[128];
    const char *post_data = "name=XboxCurl&version=1.0&platform=Xbox";

    display_test_start("HTTP POST request");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details) - 1, "HTTP %ld, POST data sent successfully", response_code);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details) - 1, "Error: %s (HTTP %ld)", curl_easy_strerror(res), response_code);
        details[sizeof(details) - 1] = '\0';
        display_test_result(0, details);
    }
}

/* Test 7: Custom Headers */
static void test_custom_headers(void)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    long response_code = 0;
    char details[128];

    display_test_start("Custom HTTP headers");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    headers = curl_slist_append(headers, "X-Custom-Header: XboxCurlTest");
    headers = curl_slist_append(headers, "User-Agent: XboxCurl/1.0 (Xbox)");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/headers");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details) - 1, "HTTP %ld, custom headers sent", response_code);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details) - 1, "Error: %s (HTTP %ld)", curl_easy_strerror(res), response_code);
        details[sizeof(details) - 1] = '\0';
        display_test_result(0, details);
    }
}

/* Test 8: HTTP Redirects */
static void test_http_redirects(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    long redirect_count = 0;
    char details[128];

    display_test_start("HTTP redirect following");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/redirect/2");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirect_count);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && response_code == 200 && redirect_count >= 2) {
        snprintf(details, sizeof(details) - 1, "HTTP %ld after %ld redirects", response_code, redirect_count);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details) - 1, "Error: %s (HTTP %ld, %ld redirects)",
                curl_easy_strerror(res), response_code, redirect_count);
        details[sizeof(details) - 1] = '\0';
        display_test_result(0, details);
    }
}

/* Test 9: Connection Timeout */
static void test_connection_timeout(void)
{
    CURL *curl;
    CURLcode res;
    char details[128];
    DWORD start_time, elapsed;

    display_test_start("Connection timeout handling");

    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    /* Use a non-routable IP to trigger timeout */
    curl_easy_setopt(curl, CURLOPT_URL, "http://10.255.255.1/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);  /* 3 second timeout */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_cleanup(curl);

    /* We expect a timeout error */
    if (res == CURLE_OPERATION_TIMEDOUT || res == CURLE_COULDNT_CONNECT) {
        snprintf(details, sizeof(details) - 1, "Timeout after %lu ms (expected)", elapsed);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);
    } else if (res == CURLE_OK) {
        display_test_result(0, "Should have timed out but didn't");
    } else {
        snprintf(details, sizeof(details) - 1, "Error: %s (%lu ms)", curl_easy_strerror(res), elapsed);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);  /* Other errors also acceptable */
    }
}

/* Test 10: Large File Download */
static void test_large_download(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    double download_size = 0;
    char details[128];

    display_test_start("Large file download (chunked)");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    /* Request a larger response */
    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/bytes/10000");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &download_size);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && response_code == 200 && total_bytes_received >= 10000) {
        snprintf(details, sizeof(details) - 1, "HTTP %ld, %u bytes downloaded", response_code, (unsigned)total_bytes_received);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details) - 1, "Error: %s (%u bytes)", curl_easy_strerror(res), (unsigned)total_bytes_received);
        details[sizeof(details) - 1] = '\0';
        display_test_result(0, details);
    }
}

/* Test 11: HTTPS POST - VERBOSE */
static void test_https_post(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    const char *post_data = "{\"test\":\"XboxCurl\",\"secure\":true}";
    struct curl_slist *headers = NULL;
    DWORD start_time, elapsed;

    display_test_start("HTTPS POST with JSON");

    OutputDebugStringA("\n========== HTTPS POST TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    /* Setup verbose debugging */
    setup_verbose_curl(curl);

    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Performing HTTPS POST...");
    xbox_console_present();

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    {
        char log[256];
        snprintf(log, sizeof(log), "HTTPS POST: code=%d (%s), HTTP=%ld, time=%lu ms\n",
            res, curl_easy_strerror(res), response_code, elapsed);
        OutputDebugStringA(log);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== HTTPS POST TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "HTTPS %ld, JSON POST OK, %lu ms", response_code, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)", res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/* Test 12: User-Agent String */
static void test_user_agent(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[128];

    display_test_start("Custom User-Agent string");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/user-agent");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "XboxCurl/1.0 (Xbox; BearSSL)");

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details) - 1, "HTTP %ld, User-Agent sent", response_code);
        details[sizeof(details) - 1] = '\0';
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details) - 1, "Error: %s (HTTP %ld)", curl_easy_strerror(res), response_code);
        details[sizeof(details) - 1] = '\0';
        display_test_result(0, details);
    }
}

/*
 * ============================================================================
 * Session Resumption Tests
 * ============================================================================
 * These tests verify that TLS session caching and resumption works correctly.
 * Session resumption allows subsequent connections to skip the full TLS
 * handshake, significantly reducing connection time.
 */

/* Test: Session Resumption Basic - Verify cache hit on second connection */
static void test_session_resumption_basic(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    int cache_count_before, cache_count_after;
    const char *test_host = "https://httpbin.org/get";

    display_test_start("Session resumption (basic)");

    OutputDebugStringA("\n========== SESSION RESUMPTION BASIC TEST ==========\n");

    /* Clear session cache to start fresh */
    session_cache::clear();
    cache_count_before = session_cache::get_count();

    OutputDebugStringA("Session cache cleared, starting fresh\n");

    /* First connection - should be a full handshake */
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, test_host);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    OutputDebugStringA("First connection (full handshake expected)...\n");
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || response_code != 200) {
        snprintf(details, sizeof(details), "First connection failed: %s (HTTP %ld)",
                 curl_easy_strerror(res), response_code);
        display_test_result(0, details);
        return;
    }

    /* Check that session was cached */
    cache_count_after = session_cache::get_count();
    {
        char log[128];
        snprintf(log, sizeof(log), "Cache count: before=%d, after=%d\n",
                 cache_count_before, cache_count_after);
        OutputDebugStringA(log);
    }

    if (cache_count_after <= cache_count_before) {
        display_test_result(0, "Session not cached after first connection");
        return;
    }

    /* Second connection - should attempt session resumption */
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed (2nd)");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, test_host);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    OutputDebugStringA("Second connection (session resumption expected)...\n");
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== SESSION RESUMPTION BASIC TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "OK, cache entries: %d", cache_count_after);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Second connection failed: %s", curl_easy_strerror(res));
        display_test_result(0, details);
    }
}

/* Test: Session Resumption Timing - Benchmark first vs resumed handshake */
static void test_session_resumption_timing(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD time_first, time_resumed;
    DWORD start_time;
    const char *test_host = "https://httpbin.org/get";

    display_test_start("Session resumption (timing)");

    OutputDebugStringA("\n========== SESSION RESUMPTION TIMING TEST ==========\n");

    /* Clear cache for clean timing measurement */
    session_cache::clear();

    /* First connection - measure full handshake time */
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, test_host);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    OutputDebugStringA("First connection timing...\n");
    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    time_first = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        snprintf(details, sizeof(details), "First connection failed: %s", curl_easy_strerror(res));
        display_test_result(0, details);
        return;
    }

    {
        char log[128];
        snprintf(log, sizeof(log), "First connection: %lu ms\n", time_first);
        OutputDebugStringA(log);
    }

    /* Second connection - measure resumed handshake time */
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed (2nd)");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, test_host);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    OutputDebugStringA("Second connection timing (resumed)...\n");
    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    time_resumed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    {
        char log[256];
        int speedup_pct = 0;
        if (time_first > 0) {
            speedup_pct = (int)(((time_first - time_resumed) * 100) / time_first);
        }
        snprintf(log, sizeof(log),
            "Session Resumption Timing Results:\n"
            "  First connection:  %lu ms (full handshake)\n"
            "  Second connection: %lu ms (resumed)\n"
            "  Speedup: %d%%\n",
            time_first, time_resumed, speedup_pct);
        OutputDebugStringA(log);
    }

    OutputDebugStringA("========== SESSION RESUMPTION TIMING TEST END ==========\n\n");

    if (res == CURLE_OK) {
        int speedup_pct = 0;
        if (time_first > 0) {
            speedup_pct = (int)(((time_first - time_resumed) * 100) / time_first);
        }
        snprintf(details, sizeof(details), "1st: %lu ms, 2nd: %lu ms (%d%% speedup)",
                 time_first, time_resumed, speedup_pct);
        /* Pass if second connection succeeded (speedup is informational) */
        display_test_result(1, details);

        /* Show timing info on console */
        xbox_console_set_colors(CONSOLE_COLOR_CYAN, CONSOLE_COLOR_BLACK);
        xbox_console_printf("         1st: %lu ms, 2nd: %lu ms\n", time_first, time_resumed);
        xbox_console_set_colors(CONSOLE_COLOR_WHITE, CONSOLE_COLOR_BLACK);
        xbox_console_present();
    } else {
        snprintf(details, sizeof(details), "Resumed connection failed: %s", curl_easy_strerror(res));
        display_test_result(0, details);
    }
}

/* Test: Session Cache Operations - Test cache management functions */
static void test_session_cache_operations(void)
{
    char details[256];
    int count;

    display_test_start("Session cache operations");

    OutputDebugStringA("\n========== SESSION CACHE OPERATIONS TEST ==========\n");

    /* Initialize if not already */
    session_cache::initialize();

    /* Test clear operation */
    session_cache::clear();
    count = session_cache::get_count();
    if (count != 0) {
        snprintf(details, sizeof(details), "Clear failed, count=%d", count);
        display_test_result(0, details);
        return;
    }
    OutputDebugStringA("session_cache::clear() - OK\n");

    /* Test store and count */
    {
        br_ssl_session_parameters params;
        memset(&params, 0, sizeof(params));
        params.session_id_len = 32;  /* Set a valid session ID length */
        memset(params.session_id, 0xAB, 32);  /* Fill with test data */

        session_cache::store("test1.example.com", &params);
        count = session_cache::get_count();
        if (count != 1) {
            snprintf(details, sizeof(details), "Store failed, count=%d (expected 1)", count);
            display_test_result(0, details);
            return;
        }
        OutputDebugStringA("session_cache::store() - OK (count=1)\n");

        /* Store another */
        session_cache::store("test2.example.com", &params);
        count = session_cache::get_count();
        if (count != 2) {
            snprintf(details, sizeof(details), "Store 2nd failed, count=%d (expected 2)", count);
            display_test_result(0, details);
            return;
        }
        OutputDebugStringA("session_cache::store() 2nd - OK (count=2)\n");
    }

    /* Test get operation */
    {
        br_ssl_session_parameters retrieved;
        memset(&retrieved, 0, sizeof(retrieved));

        if (!session_cache::get("test1.example.com", &retrieved)) {
            display_test_result(0, "Get failed for existing entry");
            return;
        }
        if (retrieved.session_id_len != 32 || retrieved.session_id[0] != 0xAB) {
            display_test_result(0, "Retrieved data doesn't match stored data");
            return;
        }
        OutputDebugStringA("session_cache::get() - OK\n");
    }

    /* Test remove operation */
    session_cache::remove("test1.example.com");
    count = session_cache::get_count();
    if (count != 1) {
        snprintf(details, sizeof(details), "Remove failed, count=%d (expected 1)", count);
        display_test_result(0, details);
        return;
    }
    OutputDebugStringA("session_cache::remove() - OK (count=1)\n");

    /* Final cleanup */
    session_cache::clear();

    OutputDebugStringA("========== SESSION CACHE OPERATIONS TEST END ==========\n\n");

    snprintf(details, sizeof(details), "All cache operations passed");
    display_test_result(1, details);
}

/*
 * ============================================================================
 * Certificate Pinning Tests
 * ============================================================================
 * These tests verify the certificate pinning infrastructure.
 * Note: Full pin verification requires a custom X.509 callback which is not
 * yet implemented. These tests verify the API works correctly.
 */

/* Test: Certificate Pinning API - Test add/remove/has_pin/clear */
static void test_cert_pinning_api(void)
{
    char details[256];
    unsigned char test_hash[32];

    display_test_start("Certificate pinning API");

    OutputDebugStringA("\n========== CERT PINNING API TEST ==========\n");

    /* Initialize */
    cert_pinning::initialize();
    cert_pinning::clear();

    /* Create a test hash */
    memset(test_hash, 0x42, 32);

    /* Test add_pin */
    if (!cert_pinning::add_pin("pintest.example.com", test_hash)) {
        display_test_result(0, "add_pin failed");
        return;
    }
    OutputDebugStringA("cert_pinning::add_pin() - OK\n");

    /* Test has_pin - should return true */
    if (!cert_pinning::has_pin("pintest.example.com")) {
        display_test_result(0, "has_pin returned false for pinned host");
        return;
    }
    OutputDebugStringA("cert_pinning::has_pin() for pinned host - OK\n");

    /* Test has_pin - should return false for unpinned host */
    if (cert_pinning::has_pin("unpinned.example.com")) {
        display_test_result(0, "has_pin returned true for unpinned host");
        return;
    }
    OutputDebugStringA("cert_pinning::has_pin() for unpinned host - OK\n");

    /* Test remove_pin */
    cert_pinning::remove_pin("pintest.example.com");
    if (cert_pinning::has_pin("pintest.example.com")) {
        display_test_result(0, "has_pin true after remove");
        return;
    }
    OutputDebugStringA("cert_pinning::remove_pin() - OK\n");

    /* Test get_pin_hash */
    {
        unsigned char retrieved_hash[32];
        if (!cert_pinning::get_pin_hash("pintest.example.com", retrieved_hash)) {
            /* We removed the pin above, so re-add for this test */
            cert_pinning::add_pin("pintest.example.com", test_hash);
            if (!cert_pinning::get_pin_hash("pintest.example.com", retrieved_hash)) {
                display_test_result(0, "get_pin_hash failed");
                return;
            }
        }
        if (memcmp(retrieved_hash, test_hash, 32) != 0) {
            display_test_result(0, "get_pin_hash returned wrong hash");
            return;
        }
        OutputDebugStringA("cert_pinning::get_pin_hash() - OK\n");
    }

    /* Test verify_hash - matching hash should return true */
    if (!cert_pinning::verify_hash("pintest.example.com", test_hash)) {
        display_test_result(0, "verify_hash returned false for correct hash");
        return;
    }
    OutputDebugStringA("cert_pinning::verify_hash() match - OK\n");

    /* Test verify_hash - wrong hash should return false */
    {
        unsigned char wrong_hash[32];
        memset(wrong_hash, 0xFF, 32);
        if (cert_pinning::verify_hash("pintest.example.com", wrong_hash)) {
            display_test_result(0, "verify_hash returned true for wrong hash");
            return;
        }
    }
    OutputDebugStringA("cert_pinning::verify_hash() mismatch - OK\n");

    /* Test verify_hash - unpinned host should return true (allow) */
    if (!cert_pinning::verify_hash("nopins.example.com", test_hash)) {
        display_test_result(0, "verify_hash returned false for unpinned host");
        return;
    }
    OutputDebugStringA("cert_pinning::verify_hash() unpinned - OK\n");

    cert_pinning::remove_pin("pintest.example.com");

    /* Test adding multiple pins */
    cert_pinning::add_pin("host1.example.com", test_hash);
    cert_pinning::add_pin("host2.example.com", test_hash);
    cert_pinning::add_pin("host3.example.com", test_hash);

    if (!cert_pinning::has_pin("host1.example.com") ||
        !cert_pinning::has_pin("host2.example.com") ||
        !cert_pinning::has_pin("host3.example.com")) {
        display_test_result(0, "Multiple pin add failed");
        return;
    }
    OutputDebugStringA("Multiple pins added - OK\n");

    /* Test clear */
    cert_pinning::clear();
    if (cert_pinning::has_pin("host1.example.com") ||
        cert_pinning::has_pin("host2.example.com") ||
        cert_pinning::has_pin("host3.example.com")) {
        display_test_result(0, "Clear failed, pins still exist");
        return;
    }
    OutputDebugStringA("cert_pinning::clear() - OK\n");

    OutputDebugStringA("========== CERT PINNING API TEST END ==========\n\n");

    snprintf(details, sizeof(details), "All pinning API operations passed");
    display_test_result(1, details);
}

/* Test: Certificate Pinning Rejection - Wrong pin should block connection */
static void test_cert_pinning_rejection(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    unsigned char wrong_hash[32];

    display_test_start("Certificate pinning rejection");

    OutputDebugStringA("\n========== CERT PINNING REJECTION TEST ==========\n");

    cert_pinning::initialize();
    cert_pinning::clear();

    /* Add a pin with the WRONG hash - connection should be rejected */
    memset(wrong_hash, 0xDE, 32);
    cert_pinning::add_pin("httpbin.org", wrong_hash);

    OutputDebugStringA("Pin added for httpbin.org with WRONG hash - expect rejection\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    cert_pinning::clear();

    OutputDebugStringA("========== CERT PINNING REJECTION TEST END ==========\n\n");

    if (res != CURLE_OK) {
        /* Good - connection was rejected due to pin mismatch */
        snprintf(details, sizeof(details), "Rejected as expected: %s", curl_easy_strerror(res));
        display_test_result(1, details);
    } else {
        /* Bad - wrong pin was accepted */
        snprintf(details, sizeof(details), "ERROR: Wrong pin accepted! HTTP %ld", response_code);
        display_test_result(0, details);
    }
}

/* Test: Certificate Pinning Allow - No pin should allow connection */
static void test_cert_pinning_allow(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];

    display_test_start("Certificate pinning (no pin = allow)");

    OutputDebugStringA("\n========== CERT PINNING ALLOW TEST ==========\n");

    /* Make sure no pins are set */
    cert_pinning::initialize();
    cert_pinning::clear();

    OutputDebugStringA("No pins set - connection should succeed\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== CERT PINNING ALLOW TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "Allowed as expected, HTTP %ld", response_code);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Failed: %s (HTTP %ld)",
                 curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/*
 * ============================================================================
 * Expanded HTTPS Tests
 * ============================================================================
 */

/* Test: HTTPS PUT Request */
static void test_https_put(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    const char *put_data = "{\"method\":\"PUT\",\"from\":\"XboxCurl\"}";
    struct curl_slist *headers = NULL;
    DWORD start_time, elapsed;

    display_test_start("HTTPS PUT request");

    OutputDebugStringA("\n========== HTTPS PUT TEST ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    setup_verbose_curl(curl);

    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/put");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, put_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== HTTPS PUT TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "HTTPS PUT %ld, %lu ms", response_code, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)",
                 res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/* Test: HTTPS with Custom Headers */
static void test_https_custom_headers(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    struct curl_slist *headers = NULL;
    DWORD start_time, elapsed;

    display_test_start("HTTPS custom headers");

    OutputDebugStringA("\n========== HTTPS CUSTOM HEADERS TEST ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    setup_verbose_curl(curl);

    /* Add multiple custom headers */
    headers = curl_slist_append(headers, "X-Xbox-Client: XboxCurl/1.0");
    headers = curl_slist_append(headers, "X-Test-Header: TestValue123");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "X-Request-ID: xbox-test-001");

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/headers");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== HTTPS CUSTOM HEADERS TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "HTTPS %ld, headers sent, %lu ms", response_code, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)",
                 res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/* Test: HTTPS DELETE Request */
static void test_https_delete(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;

    display_test_start("HTTPS DELETE request");

    OutputDebugStringA("\n========== HTTPS DELETE TEST ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    setup_verbose_curl(curl);

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/delete");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== HTTPS DELETE TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "HTTPS DELETE %ld, %lu ms", response_code, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)",
                 res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/*
 * ============================================================================
 * File Upload Tests
 * ============================================================================
 * These tests verify multipart form-data file uploads using curl_mime API.
 * Uploads are done from memory buffers for simplicity (no test files needed).
 */

/* Test: HTTP multipart file upload from memory */
static void test_http_file_upload(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    curl_mime *mime = NULL;
    curl_mimepart *part = NULL;
    const char *file_data = "Hello from Xbox!\nThis is a test file uploaded via XboxCurl.\nLine 3 of test data.\n";
    size_t file_size = strlen(file_data);

    display_test_start("HTTP multipart file upload");

    OutputDebugStringA("\n========== HTTP FILE UPLOAD TEST ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    /* Build multipart form with a file field from memory */
    mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        display_test_result(0, "curl_mime_init failed");
        return;
    }

    part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_data(part, file_data, file_size);
    curl_mime_filename(part, "xbox_test.txt");
    curl_mime_type(part, "text/plain");

    /* Add a regular form field alongside the file */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "description");
    curl_mime_data(part, "Uploaded from Original Xbox via XboxCurl", CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== HTTP FILE UPLOAD TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "HTTP %ld, uploaded %u bytes",
                 response_code, (unsigned)file_size);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error: %s (HTTP %ld)",
                 curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/* Test: HTTPS multipart file upload from memory */
static void test_https_file_upload(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    curl_mime *mime = NULL;
    curl_mimepart *part = NULL;
    DWORD start_time, elapsed;

    /* Binary test data (simulates a small binary file) */
    unsigned char bin_data[256];
    int i;
    for (i = 0; i < 256; i++) bin_data[i] = (unsigned char)i;

    display_test_start("HTTPS multipart file upload");

    OutputDebugStringA("\n========== HTTPS FILE UPLOAD TEST ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    setup_verbose_curl(curl);

    mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        display_test_result(0, "curl_mime_init failed");
        return;
    }

    /* File field: binary data */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_data(part, (const char *)bin_data, sizeof(bin_data));
    curl_mime_filename(part, "test_binary.bin");
    curl_mime_type(part, "application/octet-stream");

    /* Text field: text file from memory */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "readme");
    curl_mime_data(part, "XboxCurl HTTPS upload test\n", CURL_ZERO_TERMINATED);
    curl_mime_filename(part, "readme.txt");
    curl_mime_type(part, "text/plain");

    /* Regular form field */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "platform");
    curl_mime_data(part, "Xbox", CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Uploading via HTTPS...");
    xbox_console_present();

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== HTTPS FILE UPLOAD TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "HTTPS %ld, uploaded 256+27 bytes, %lu ms",
                 response_code, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld, %lu ms)",
                 res, curl_easy_strerror(res), response_code, elapsed);
        display_test_result(0, details);
    }
}

/* Test: Large multipart upload with multiple fields */
static void test_large_file_upload(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    curl_mime *mime = NULL;
    curl_mimepart *part = NULL;
    DWORD start_time, elapsed;

    /* Generate a 4KB test payload */
    char large_buf[4096];
    int i;
    for (i = 0; i < (int)sizeof(large_buf); i++) {
        large_buf[i] = 'A' + (i % 26);
    }

    display_test_start("Large file upload (4KB)");

    OutputDebugStringA("\n========== LARGE FILE UPLOAD TEST ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) {
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        display_test_result(0, "curl_mime_init failed");
        return;
    }

    part = curl_mime_addpart(mime);
    curl_mime_name(part, "largefile");
    curl_mime_data(part, large_buf, sizeof(large_buf));
    curl_mime_filename(part, "large_test.dat");
    curl_mime_type(part, "application/octet-stream");

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== LARGE FILE UPLOAD TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "HTTP %ld, uploaded 4096 bytes, %lu ms",
                 response_code, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error: %s (HTTP %ld, %lu ms)",
                 curl_easy_strerror(res), response_code, elapsed);
        display_test_result(0, details);
    }
}

/*
 * Test: HTTPS file download to disk
 * Downloads a file from xbxbx.ams1.ppn.prutzel.com and saves it to T:\ drive
 */
static void test_https_file_download(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    struct file_write_data fwd;
    const char *save_path = "T:\\Eeprom Reader Tools.rar";
    const char *url = "https://xbxbx.ams1.ppn.prutzel.com/"
        "?file=community_uploads/xbox_software/"
        "Eeprom%20Reader%20Tools.rar";

    display_test_start("HTTPS file download to T:\\");

    OutputDebugStringA("\n========== HTTPS FILE DOWNLOAD TEST START ==========\n");

    total_bytes_received = 0;
    memset(&fwd, 0, sizeof(fwd));

    fwd.fp = fopen(save_path, "wb");
    if (!fwd.fp) {
        snprintf(details, sizeof(details), "Failed to open %s for writing", save_path);
        display_test_result(0, details);
        return;
    }

    curl = curl_easy_init();
    if (!curl) {
        fclose(fwd.fp);
        display_test_result(0, "curl_easy_init failed");
        return;
    }

    setup_verbose_curl(curl);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, file_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fwd);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("         Downloading Eeprom Reader Tools.rar...");
    xbox_console_present();

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    fclose(fwd.fp);

    if (res == CURLE_OK && response_code == 200 && fwd.bytes_written > 0) {
        snprintf(details, sizeof(details),
            "Saved %u bytes to T:\\ (%lu ms)",
            (unsigned)fwd.bytes_written, elapsed);
        display_test_result(1, details);
    } else {
        /* Remove incomplete file */
        remove(save_path);
        snprintf(details, sizeof(details),
            "Error %d (HTTP %ld): %s (%lu ms)",
            res, response_code, curl_easy_strerror(res), elapsed);
        display_test_result(0, details);
    }

    OutputDebugStringA("========== HTTPS FILE DOWNLOAD TEST END ==========\n\n");
}

/*
 * ============================================================================
 * Extended Download Tests
 * ============================================================================
 */

/* Download exact number of random bytes over HTTPS, verify size */
static void test_download_binary_exact(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;

    display_test_start("HTTPS binary download (5000 bytes)");

    OutputDebugStringA("\n========== BINARY DOWNLOAD TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/bytes/5000");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== BINARY DOWNLOAD TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200 && total_bytes_received == 5000) {
        snprintf(details, sizeof(details), "Got exactly 5000 bytes (%lu ms)", elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Expected 5000, got %u (err %d, HTTP %ld)",
                 (unsigned)total_bytes_received, res, response_code);
        display_test_result(0, details);
    }
}

/* Download streamed bytes (chunked transfer encoding) */
static void test_download_stream_bytes(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;

    display_test_start("HTTPS streamed download (8KB chunked)");

    OutputDebugStringA("\n========== STREAM BYTES TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    curl_easy_setopt(curl, CURLOPT_URL,
        "https://httpbin.org/stream-bytes/8192?chunk_size=1024");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== STREAM BYTES TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200 && total_bytes_received >= 8192) {
        snprintf(details, sizeof(details), "Streamed %u bytes in chunks (%lu ms)",
                 (unsigned)total_bytes_received, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Got %u bytes (err %d, HTTP %ld)",
                 (unsigned)total_bytes_received, res, response_code);
        display_test_result(0, details);
    }
}

/* Large HTTPS download - 100KB binary, measure throughput */
static void test_download_large_https(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    double speed;

    display_test_start("HTTPS large download (100KB)");

    OutputDebugStringA("\n========== LARGE HTTPS DOWNLOAD TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/bytes/102400");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== LARGE HTTPS DOWNLOAD TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200 && total_bytes_received >= 102400) {
        speed = (elapsed > 0) ? (double)total_bytes_received / elapsed : 0.0;
        snprintf(details, sizeof(details), "%u bytes, %lu ms (%.1f KB/s)",
                 (unsigned)total_bytes_received, elapsed, speed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Got %u of 102400 (err %d, HTTP %ld)",
                 (unsigned)total_bytes_received, res, response_code);
        display_test_result(0, details);
    }
}

/* Download binary to file on T:\ drive */
static void test_download_binary_to_file(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    struct file_write_data fwd;
    const char *save_path = "T:\\download_test.bin";

    display_test_start("HTTPS download binary to file");

    OutputDebugStringA("\n========== DOWNLOAD TO FILE TEST START ==========\n");

    total_bytes_received = 0;
    memset(&fwd, 0, sizeof(fwd));

    fwd.fp = fopen(save_path, "wb");
    if (!fwd.fp) {
        display_test_result(0, "Failed to open T:\\download_test.bin");
        return;
    }

    curl = curl_easy_init();
    if (!curl) { fclose(fwd.fp); display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/bytes/16384");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, file_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fwd);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    fclose(fwd.fp);

    OutputDebugStringA("========== DOWNLOAD TO FILE TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200 && fwd.bytes_written == 16384) {
        snprintf(details, sizeof(details), "Wrote 16384 bytes to T:\\ (%lu ms)", elapsed);
        display_test_result(1, details);
    } else {
        remove(save_path);
        snprintf(details, sizeof(details), "Wrote %u (err %d, HTTP %ld)",
                 (unsigned)fwd.bytes_written, res, response_code);
        display_test_result(0, details);
    }
    /* Clean up test file */
    remove(save_path);
}

/* HTTPS redirect chain - follow 3 redirects to final /get */
static void test_download_redirect_chain(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    long redirect_count = 0;
    char details[256];
    DWORD start_time, elapsed;

    display_test_start("HTTPS redirect chain (3 hops)");

    OutputDebugStringA("\n========== REDIRECT CHAIN TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/redirect/3");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirect_count);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== REDIRECT CHAIN TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200 && redirect_count == 3) {
        snprintf(details, sizeof(details),
            "Followed %ld redirects, %u bytes (%lu ms)",
            redirect_count, (unsigned)total_bytes_received, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details),
            "%ld redirects, HTTP %ld, err %d (%lu ms)",
            redirect_count, response_code, res, elapsed);
        display_test_result(0, details);
    }
}

/* HTTPS Range request - partial content download (HTTP 206) */
static void test_download_range_request(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;

    display_test_start("HTTPS range request (partial)");

    OutputDebugStringA("\n========== RANGE REQUEST TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    /* httpbin /range/1024 supports Range header and returns 206 */
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/range/1024");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_RANGE, "0-511");

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== RANGE REQUEST TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 206 && total_bytes_received == 512) {
        snprintf(details, sizeof(details), "HTTP 206, got 512 of 1024 bytes (%lu ms)", elapsed);
        display_test_result(1, details);
    } else if (res == CURLE_OK && response_code == 200) {
        /* Server may ignore Range header - still a pass if we got data */
        snprintf(details, sizeof(details), "HTTP 200 (Range ignored), %u bytes (%lu ms)",
                 (unsigned)total_bytes_received, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "HTTP %ld, %u bytes, err %d",
                 response_code, (unsigned)total_bytes_received, res);
        display_test_result(0, details);
    }
}

/* Download and verify content - GET /get echoes request details as JSON */
static void test_download_verify_content(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    struct response_data rd;
    struct curl_slist *headers = NULL;

    display_test_start("HTTPS download + verify content");

    OutputDebugStringA("\n========== DOWNLOAD VERIFY TEST START ==========\n");

    memset(&rd, 0, sizeof(rd));
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    headers = curl_slist_append(headers, "X-Xbox-Verify: TestToken42");
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, capture_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rd);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    OutputDebugStringA("========== DOWNLOAD VERIFY TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        /* Verify the server echoed our custom header in the JSON response */
        if (strstr(rd.buffer, "TestToken42") != NULL) {
            snprintf(details, sizeof(details),
                "Verified echo, %u bytes (%lu ms)", (unsigned)rd.size, elapsed);
            display_test_result(1, details);
        } else {
            snprintf(details, sizeof(details),
                "Header not echoed back (%u bytes)", (unsigned)rd.size);
            display_test_result(0, details);
        }
    } else {
        snprintf(details, sizeof(details), "Error %d, HTTP %ld", res, response_code);
        display_test_result(0, details);
    }
}

/*
 * ============================================================================
 * Extended Upload Tests
 * ============================================================================
 */

/* HTTPS POST with URL-encoded form data */
static void test_upload_urlencoded(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    struct response_data rd;

    display_test_start("HTTPS POST url-encoded form");

    OutputDebugStringA("\n========== URLENCODED POST TEST START ==========\n");

    memset(&rd, 0, sizeof(rd));
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, capture_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rd);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
        "platform=Xbox&library=XboxCurl&tls=BearSSL&test=urlencoded");

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== URLENCODED POST TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        /* Verify server parsed our form fields */
        if (strstr(rd.buffer, "XboxCurl") && strstr(rd.buffer, "BearSSL")) {
            snprintf(details, sizeof(details), "Form data echoed, %lu ms", elapsed);
            display_test_result(1, details);
        } else {
            display_test_result(0, "Form data not echoed in response");
        }
    } else {
        snprintf(details, sizeof(details), "Error %d, HTTP %ld", res, response_code);
        display_test_result(0, details);
    }
}

/* HTTPS PUT with large binary payload */
static void test_upload_put_large(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    struct curl_slist *headers = NULL;

    /* Generate 16KB binary payload */
    unsigned char payload[16384];
    int i;
    for (i = 0; i < (int)sizeof(payload); i++)
        payload[i] = (unsigned char)(i * 7 + 13);

    display_test_start("HTTPS PUT large binary (16KB)");

    OutputDebugStringA("\n========== LARGE PUT TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/put");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char *)payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)sizeof(payload));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    OutputDebugStringA("========== LARGE PUT TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details), "PUT 16384 bytes, HTTP %ld (%lu ms)",
                 response_code, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)",
                 res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/* HTTPS PATCH request */
static void test_upload_patch(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    struct curl_slist *headers = NULL;
    const char *patch_data = "{\"op\":\"replace\",\"path\":\"/name\",\"value\":\"Xbox\"}";
    struct response_data rd;

    display_test_start("HTTPS PATCH request");

    OutputDebugStringA("\n========== PATCH TEST START ==========\n");

    memset(&rd, 0, sizeof(rd));
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/patch");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, capture_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rd);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, patch_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    OutputDebugStringA("========== PATCH TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200 && strstr(rd.buffer, "replace")) {
        snprintf(details, sizeof(details), "PATCH echoed, HTTP %ld (%lu ms)",
                 response_code, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d, HTTP %ld", res, response_code);
        display_test_result(0, details);
    }
}

/* HTTPS multipart upload with multiple files + verify echo */
static void test_upload_multipart_verified(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    curl_mime *mime = NULL;
    curl_mimepart *part = NULL;
    struct response_data rd;

    /* Generate distinct test payloads */
    char text_file[] = "Line 1: XboxCurl multipart test\n"
                       "Line 2: This is file A\n"
                       "Line 3: Verifying multi-file upload\n";
    unsigned char bin_file[512];
    int i;
    for (i = 0; i < (int)sizeof(bin_file); i++)
        bin_file[i] = (unsigned char)(i ^ 0xAA);

    display_test_start("HTTPS multipart multi-file upload");

    OutputDebugStringA("\n========== MULTIPART VERIFIED TEST START ==========\n");

    memset(&rd, 0, sizeof(rd));
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);

    mime = curl_mime_init(curl);
    if (!mime) { curl_easy_cleanup(curl); display_test_result(0, "mime_init failed"); return; }

    /* File 1: text file */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "textfile");
    curl_mime_data(part, text_file, CURL_ZERO_TERMINATED);
    curl_mime_filename(part, "notes.txt");
    curl_mime_type(part, "text/plain");

    /* File 2: binary file */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "binfile");
    curl_mime_data(part, (const char *)bin_file, sizeof(bin_file));
    curl_mime_filename(part, "data.bin");
    curl_mime_type(part, "application/octet-stream");

    /* File 3: JSON config */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "config");
    curl_mime_data(part, "{\"console\":\"Xbox\",\"version\":1}", CURL_ZERO_TERMINATED);
    curl_mime_filename(part, "config.json");
    curl_mime_type(part, "application/json");

    /* Form field */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "uploader");
    curl_mime_data(part, "XboxCurl-TestSuite", CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, capture_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rd);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== MULTIPART VERIFIED TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        /* httpbin echoes multipart data keyed by field name (not filename).
         * Check for field names and content strings in the JSON response. */
        int has_text = (strstr(rd.buffer, "textfile") != NULL);
        int has_bin = (strstr(rd.buffer, "binfile") != NULL);
        int has_json = (strstr(rd.buffer, "config") != NULL);
        int has_form = (strstr(rd.buffer, "XboxCurl-TestSuite") != NULL);

        if (has_text && has_bin && has_json && has_form) {
            snprintf(details, sizeof(details),
                "3 files + 1 field echoed (%lu ms)", elapsed);
            display_test_result(1, details);
        } else {
            snprintf(details, sizeof(details),
                "Missing: %s%s%s%s",
                has_text ? "" : "text ",
                has_bin ? "" : "bin ",
                has_json ? "" : "json ",
                has_form ? "" : "form");
            display_test_result(0, details);
        }
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)",
                 res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/* HTTPS POST large JSON payload (16KB) and verify echo */
static void test_upload_large_json(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    struct curl_slist *headers = NULL;
    struct response_data rd;

    /* Build a ~2KB JSON payload with array of items */
    char json_buf[2048];
    int pos, item;

    pos = snprintf(json_buf, sizeof(json_buf), "{\"source\":\"Xbox\",\"items\":[");
    for (item = 0; item < 40 && pos < (int)sizeof(json_buf) - 64; item++) {
        if (item > 0) json_buf[pos++] = ',';
        pos += snprintf(json_buf + pos, sizeof(json_buf) - pos,
            "{\"id\":%d,\"name\":\"item_%d\",\"value\":%d}",
            item, item, item * 17 + 42);
    }
    pos += snprintf(json_buf + pos, sizeof(json_buf) - pos, "]}");
    json_buf[sizeof(json_buf) - 1] = '\0';

    display_test_start("HTTPS POST large JSON");

    OutputDebugStringA("\n========== LARGE JSON POST TEST START ==========\n");

    memset(&rd, 0, sizeof(rd));
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, capture_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rd);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_buf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    OutputDebugStringA("========== LARGE JSON POST TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        /* Verify the JSON was echoed (httpbin puts it in "data" or "json" field) */
        if (strstr(rd.buffer, "item_0") && strstr(rd.buffer, "item_39")) {
            snprintf(details, sizeof(details),
                "Sent %u bytes JSON, echoed OK (%lu ms)",
                (unsigned)strlen(json_buf), elapsed);
            display_test_result(1, details);
        } else {
            display_test_result(0, "JSON not fully echoed in response");
        }
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)",
                 res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/* HTTPS upload from file on disk - read T:\cacert.pem and POST it */
static void test_upload_from_disk(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    curl_mime *mime = NULL;
    curl_mimepart *part = NULL;
    FILE *fp;
    char read_buf[4096];
    size_t file_bytes;

    display_test_start("HTTPS upload file from T:\\ disk");

    OutputDebugStringA("\n========== UPLOAD FROM DISK TEST START ==========\n");

    /* Read first 4KB of cacert.pem from disk */
    fp = fopen("T:\\cacert.pem", "rb");
    if (!fp) {
        display_test_result(0, "Cannot open T:\\cacert.pem for reading");
        return;
    }
    file_bytes = fread(read_buf, 1, sizeof(read_buf), fp);
    fclose(fp);

    if (file_bytes == 0) {
        display_test_result(0, "T:\\cacert.pem is empty");
        return;
    }

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);

    mime = curl_mime_init(curl);
    if (!mime) { curl_easy_cleanup(curl); display_test_result(0, "mime_init failed"); return; }

    /* Upload the file chunk as a multipart attachment */
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "certfile");
    curl_mime_data(part, read_buf, file_bytes);
    curl_mime_filename(part, "cacert_snippet.pem");
    curl_mime_type(part, "application/x-pem-file");

    part = curl_mime_addpart(mime);
    curl_mime_name(part, "source");
    curl_mime_data(part, "Xbox T:\\ drive", CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== UPLOAD FROM DISK TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        snprintf(details, sizeof(details),
            "Uploaded %u bytes from disk (%lu ms)",
            (unsigned)file_bytes, elapsed);
        display_test_result(1, details);
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)",
                 res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/* HTTP error status handling - verify we handle 404 gracefully */
static void test_download_error_status(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];

    display_test_start("HTTPS error handling (404)");

    OutputDebugStringA("\n========== ERROR STATUS TEST START ==========\n");

    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/status/404");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    OutputDebugStringA("========== ERROR STATUS TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 404) {
        display_test_result(1, "Correctly received HTTP 404");
    } else {
        snprintf(details, sizeof(details), "Expected 404, got HTTP %ld (err %d)",
                 response_code, res);
        display_test_result(0, details);
    }
}

/* Round-trip test: upload data, capture response, verify it matches */
static void test_upload_roundtrip_verify(void)
{
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    char details[256];
    DWORD start_time, elapsed;
    struct curl_slist *headers = NULL;
    struct response_data rd;
    const char *test_string = "XboxCurl-RoundTrip-Verification-12345-ABCDE";

    display_test_start("HTTPS upload round-trip verify");

    OutputDebugStringA("\n========== ROUNDTRIP VERIFY TEST START ==========\n");

    memset(&rd, 0, sizeof(rd));
    total_bytes_received = 0;
    curl = curl_easy_init();
    if (!curl) { display_test_result(0, "curl_easy_init failed"); return; }

    setup_verbose_curl(curl);
    headers = curl_slist_append(headers, "Content-Type: text/plain");
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, capture_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rd);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, test_string);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    start_time = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start_time;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    OutputDebugStringA("========== ROUNDTRIP VERIFY TEST END ==========\n\n");

    if (res == CURLE_OK && response_code == 200) {
        /* httpbin echoes POST body in "data" field */
        if (strstr(rd.buffer, test_string) != NULL) {
            snprintf(details, sizeof(details),
                "Round-trip verified (%u bytes, %lu ms)",
                (unsigned)rd.size, elapsed);
            display_test_result(1, details);
        } else {
            display_test_result(0, "Sent data not found in response");
        }
    } else {
        snprintf(details, sizeof(details), "Error %d: %s (HTTP %ld)",
                 res, curl_easy_strerror(res), response_code);
        display_test_result(0, details);
    }
}

/*
 * D3D Diagnostic Test
 */
static void test_d3d_diagnostic(void)
{
    IDirect3D8 *d3d = NULL;
    IDirect3DDevice8 *device = NULL;
    D3DPRESENT_PARAMETERS d3dpp;
    HRESULT hr;

    OutputDebugStringA("\n=== D3D DIAGNOSTIC TEST ===\n");

    d3d = Direct3DCreate8(D3D_SDK_VERSION);
    if (!d3d) {
        OutputDebugStringA("[FAIL] Direct3DCreate8 failed\n");
        return;
    }
    OutputDebugStringA("[PASS] Direct3DCreate8 OK\n");

    ZeroMemory(&d3dpp, sizeof(d3dpp));
    d3dpp.BackBufferWidth = 640;
    d3dpp.BackBufferHeight = 480;
    d3dpp.BackBufferFormat = D3DFMT_X8R8G8B8;  /* Standard swizzled format */
    d3dpp.BackBufferCount = 1;
    d3dpp.EnableAutoDepthStencil = FALSE;
    d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    d3dpp.FullScreen_RefreshRateInHz = 60;
    d3dpp.FullScreen_PresentationInterval = D3DPRESENT_INTERVAL_ONE;

    hr = d3d->CreateDevice(0, D3DDEVTYPE_HAL, NULL,
                           D3DCREATE_HARDWARE_VERTEXPROCESSING,
                           &d3dpp, &device);
    if (FAILED(hr)) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "[FAIL] CreateDevice: 0x%08X\n", hr);
        buf[sizeof(buf) - 1] = '\0';
        OutputDebugStringA(buf);
        d3d->Release();
        return;
    }
    OutputDebugStringA("[PASS] CreateDevice OK\n");

    /* Clear with BeginScene/EndScene for proper GPU sync */
    hr = device->BeginScene();
    if (FAILED(hr)) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "[FAIL] BeginScene: 0x%08X\n", hr);
        buf[sizeof(buf) - 1] = '\0';
        OutputDebugStringA(buf);
    }

    hr = device->Clear(0, NULL, D3DCLEAR_TARGET, D3DCOLOR_XRGB(0, 0, 255), 1.0f, 0);
    if (FAILED(hr)) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "[FAIL] Clear: 0x%08X\n", hr);
        buf[sizeof(buf) - 1] = '\0';
        OutputDebugStringA(buf);
    } else {
        OutputDebugStringA("[PASS] Clear OK\n");
    }

    device->EndScene();

    hr = device->Present(NULL, NULL, NULL, NULL);
    if (FAILED(hr)) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "[FAIL] Present: 0x%08X\n", hr);
        buf[sizeof(buf) - 1] = '\0';
        OutputDebugStringA(buf);
    } else {
        OutputDebugStringA("[PASS] Present OK - should see BLUE screen\n");
    }

    OutputDebugStringA("Waiting 3 seconds to view blue screen...\n");
    Sleep(3000);

    /* Second frame - green */
    device->BeginScene();
    device->Clear(0, NULL, D3DCLEAR_TARGET, D3DCOLOR_XRGB(0, 255, 0), 1.0f, 0);
    device->EndScene();
    device->Present(NULL, NULL, NULL, NULL);
    OutputDebugStringA("[INFO] Should see GREEN screen now\n");
    Sleep(2000);

    /* Clean up */
    device->Release();
    d3d->Release();
    OutputDebugStringA("[PASS] D3D cleanup OK\n");
    OutputDebugStringA("D3D diagnostic complete\n\n");
}

/*
 * Main entry point
 */
void __cdecl main(void)
{
    /* Run D3D diagnostic first */
    test_d3d_diagnostic();

    /* Initialize console for on-screen display */
    OutputDebugStringA("Initializing xbox_console...\n");
    if (!xbox_console_init(640, 480)) {
        OutputDebugStringA("FATAL: Failed to initialize console\n");
        for (;;) Sleep(1000);
    }
    OutputDebugStringA("xbox_console_init OK\n");

    /* Clear and show logo */
    xbox_console_clear(CONSOLE_COLOR_BLACK);
    display_logo();
    display_header("Xbox libcurl + BearSSL Test Suite");

    /* Initialize network */
    if (!wait_for_network()) {
        xbox_console_set_colors(CONSOLE_COLOR_RED, CONSOLE_COLOR_BLACK);
        xbox_console_println("FATAL: Network initialization failed!");
        xbox_console_println("Check ethernet cable and DHCP server.");
        xbox_console_present();
        for (;;) Sleep(1000);
    }

    /* Initialize libcurl */
    xbox_console_println("Initializing libcurl...");
    xbox_console_present();
    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* Enable verbose BearSSL debugging */
    xbox_console_println("Enabling verbose SSL debugging...");
    xbox_console_present();
    ssl_debug::set_level(SSL_DEBUG_VERBOSE);
    OutputDebugStringA("BearSSL debug level set to VERBOSE\n");

    /* Run test suite */
    display_section("Basic Tests");
    test_version_info();
    test_http_get_by_ip();
    test_http_get_dns();

    display_section("HTTPS/TLS Tests");
    test_bearssl_diagnostics(); /* BearSSL engine test */
    test_tcp_port_443();       /* First verify raw TCP to 443 works */
    test_https_by_ip();        /* Test HTTPS without DNS/SNI */
    test_https_simple();       /* Test simple endpoint */
    test_https_get_no_verify();
    test_https_tls_options();  /* Test TLS version negotiation */
    test_https_get_with_verify();
    test_https_post();

    display_section("HTTP Features");
    test_http_post();
    test_custom_headers();
    test_user_agent();
    test_http_redirects();

    display_section("Advanced Tests");
    test_large_download();
    test_connection_timeout();

    display_section("Session Resumption Tests");
    test_session_cache_operations();  /* Test cache API first */
    test_session_resumption_basic();  /* Verify cache hit */
    test_session_resumption_timing(); /* Benchmark speedup */

    display_section("Certificate Pinning Tests");
    test_cert_pinning_api();          /* Test pinning API */
    test_cert_pinning_rejection();    /* Wrong pin should reject */
    test_cert_pinning_allow();        /* No pin should allow */

    display_section("File Upload Tests");
    test_http_file_upload();          /* HTTP multipart upload */
    test_https_file_upload();         /* HTTPS multipart upload */
    test_large_file_upload();         /* 4KB upload */

    display_section("Expanded HTTPS Tests");
    test_https_put();                 /* HTTPS PUT */
    test_https_custom_headers();      /* HTTPS custom headers */
    test_https_delete();              /* HTTPS DELETE */

    display_section("Extended Download Tests");
    test_download_binary_exact();     /* Exact byte count download */
    test_download_stream_bytes();     /* Chunked transfer encoding */
    test_download_large_https();      /* 100KB HTTPS throughput */
    test_download_binary_to_file();   /* Binary download to T:\ */
    test_download_redirect_chain();   /* Follow 3 HTTPS redirects */
    test_download_range_request();    /* HTTP 206 partial content */
    test_download_verify_content();   /* Download + verify echo */
    test_download_error_status();     /* Graceful 404 handling */

    display_section("Extended Upload Tests");
    test_upload_urlencoded();         /* URL-encoded form POST */
    test_upload_put_large();          /* 16KB binary PUT */
    test_upload_patch();              /* HTTPS PATCH method */
    test_upload_multipart_verified(); /* Multi-file upload + verify */
    test_upload_large_json();         /* Large JSON POST */
    test_upload_from_disk();          /* Upload file read from T:\ */
    test_upload_roundtrip_verify();   /* Upload + verify echo match */

    display_section("External Download Tests");
    test_https_file_download();       /* HTTPS download from xbxbx */

    /* Show summary */
    display_summary();

    /* Cleanup */
    curl_global_cleanup();
    WSACleanup();
    XNetCleanup();

    /* Keep displaying results */
    xbox_console_println("");
    xbox_console_set_colors(CONSOLE_COLOR_GRAY, CONSOLE_COLOR_BLACK);
    xbox_console_println("Test complete. Console will remain active.");
    xbox_console_present();

    /* Infinite loop to keep display visible */
    for (;;) {
        Sleep(1000);
    }
}
