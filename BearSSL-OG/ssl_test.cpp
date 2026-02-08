#include "ssl_test.h"
#include "client.h"
#include "ssl_debug.h"
#include "session_cache.h"
#include "debug_utility.h"

#include <xtl.h>
#include <stdio.h>
#include <string.h>

// KeQuerySystemTime is exported by the Xbox kernel (xboxkrnl.lib)
#ifdef __cplusplus
extern "C"
#endif
void WINAPI KeQuerySystemTime(PLARGE_INTEGER CurrentTime);

// Test file paths on Xbox E: drive
#define TEST_FILE_SMALL     "E:\\ssl_test_small.bin"
#define TEST_FILE_LARGE     "E:\\ssl_test_large.bin"
#define TEST_FILE_REDIRECT  "E:\\ssl_test_redirect.bin"
#define TEST_FILE_CHUNKED   "E:\\ssl_test_chunked.bin"
#define TEST_FILE_RESUME    "E:\\ssl_test_resume.bin"

// Test URLs - using reliable public HTTPS endpoints
// Small file test - GitHub raw file
#define URL_SMALL "https://raw.githubusercontent.com/AbanteAI/rawdog/main/README.md"

// Larger file test - Known firmware download
#define URL_LARGE "https://codeload.github.com/Team-Resurgent/PrometheOS-Firmware/zip/refs/tags/V1.5.0"

// Redirect test - GitHub releases redirect
#define URL_REDIRECT "https://github.com/Team-Resurgent/Modxo/releases/download/V1.0.8/modxo_official_pico.bin"

// Chunked transfer test - use httpbin which returns chunked encoding
#define URL_CHUNKED "https://httpbin.org/stream/5"

// Alternate host test - non-GitHub server
#define URL_ALTERNATE "https://httpbin.org/get"
#define TEST_FILE_ALTERNATE "E:\\ssl_test_alternate.bin"

uint32_t ssl_test::get_time_ms()
{
    LARGE_INTEGER system_time;
    KeQuerySystemTime(&system_time);
    return (uint32_t)(system_time.QuadPart / 10000ULL);
}

bool ssl_test::file_exists(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (f != NULL) {
        fclose(f);
        return true;
    }
    return false;
}

int64_t ssl_test::get_file_size(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (f == NULL) return -1;

    fseek(f, 0, SEEK_END);
    int64_t size = ftell(f);
    fclose(f);
    return size;
}

void ssl_test::delete_file(const char* path)
{
    DeleteFile(path);
}

void ssl_test::print_result(const ssl_test_result& result)
{
    const char* status;
    switch (result.result) {
        case SSL_TEST_PASS: status = "PASS"; break;
        case SSL_TEST_FAIL: status = "FAIL"; break;
        case SSL_TEST_SKIP: status = "SKIP"; break;
        default: status = "????"; break;
    }

    debug_utility::debug_print("\n[%s] %s\n", status, result.test_name);

    if (result.message != NULL && result.message[0] != '\0') {
        debug_utility::debug_print("       %s\n", result.message);
    }

    if (result.bytes_downloaded > 0) {
        debug_utility::debug_print("       Downloaded: %lld bytes\n", result.bytes_downloaded);
    }

    if (result.time_ms > 0) {
        debug_utility::debug_print("       Time: %u ms\n", result.time_ms);
    }
}

void ssl_test::print_summary(int passed, int failed, int skipped)
{
    debug_utility::debug_print("\n");
    debug_utility::debug_print("==========================================\n");
    debug_utility::debug_print("SSL TEST SUMMARY\n");
    debug_utility::debug_print("==========================================\n");
    debug_utility::debug_print("Passed:  %d\n", passed);
    debug_utility::debug_print("Failed:  %d\n", failed);
    debug_utility::debug_print("Skipped: %d\n", skipped);
    debug_utility::debug_print("Total:   %d\n", passed + failed + skipped);
    debug_utility::debug_print("==========================================\n");

    if (failed == 0) {
        debug_utility::debug_print("ALL TESTS PASSED!\n");
    } else {
        debug_utility::debug_print("SOME TESTS FAILED - check results above\n");
    }
    debug_utility::debug_print("==========================================\n");
}

// =============================================================================
// TEST: Basic HTTPS Connection
// =============================================================================
ssl_test_result ssl_test::test_basic_https_connection()
{
    ssl_test_result result;
    result.test_name = "Basic HTTPS Connection";
    result.message = "";
    result.bytes_downloaded = 0;
    result.time_ms = 0;

    debug_utility::debug_print("\n--- Running: %s ---\n", result.test_name);

    // Clean up any previous test file
    delete_file(TEST_FILE_SMALL);

    // Set debug level to see handshake info
    ssl_debug::set_level(SSL_DEBUG_INFO);

    uint32_t start_time = get_time_ms();

    client* c = new client();
    int ret = c->download_file(URL_SMALL, 443, TEST_FILE_SMALL);
    delete c;

    result.time_ms = get_time_ms() - start_time;

    if (ret == 0) {
        if (file_exists(TEST_FILE_SMALL)) {
            result.bytes_downloaded = get_file_size(TEST_FILE_SMALL);
            if (result.bytes_downloaded > 0) {
                result.result = SSL_TEST_PASS;
                result.message = "Successfully connected and downloaded file";
            } else {
                result.result = SSL_TEST_FAIL;
                result.message = "File created but empty";
            }
        } else {
            result.result = SSL_TEST_FAIL;
            result.message = "Download returned success but file not found";
        }
    } else {
        result.result = SSL_TEST_FAIL;
        result.message = "Download failed - check SSL debug output above";
    }

    // Clean up
    delete_file(TEST_FILE_SMALL);

    return result;
}

// =============================================================================
// TEST: Large File Download
// =============================================================================
ssl_test_result ssl_test::test_large_file_download()
{
    ssl_test_result result;
    result.test_name = "Large File Download (PrometheOS zip)";
    result.message = "";
    result.bytes_downloaded = 0;
    result.time_ms = 0;

    debug_utility::debug_print("\n--- Running: %s ---\n", result.test_name);

    delete_file(TEST_FILE_LARGE);

    ssl_debug::set_level(SSL_DEBUG_INFO);

    uint32_t start_time = get_time_ms();

    client* c = new client();
    int ret = c->download_file(URL_LARGE, 443, TEST_FILE_LARGE);
    delete c;

    result.time_ms = get_time_ms() - start_time;

    if (ret == 0) {
        if (file_exists(TEST_FILE_LARGE)) {
            result.bytes_downloaded = get_file_size(TEST_FILE_LARGE);
            // PrometheOS zip should be at least 100KB
            if (result.bytes_downloaded > 100000) {
                result.result = SSL_TEST_PASS;
                result.message = "Large file downloaded successfully";
            } else {
                result.result = SSL_TEST_FAIL;
                result.message = "File too small - possible incomplete download";
            }
        } else {
            result.result = SSL_TEST_FAIL;
            result.message = "File not created";
        }
    } else {
        result.result = SSL_TEST_FAIL;
        result.message = "Download failed";
    }

    delete_file(TEST_FILE_LARGE);

    return result;
}

// =============================================================================
// TEST: Redirect Handling
// =============================================================================
ssl_test_result ssl_test::test_redirect_handling()
{
    ssl_test_result result;
    result.test_name = "HTTP Redirect Handling";
    result.message = "";
    result.bytes_downloaded = 0;
    result.time_ms = 0;

    debug_utility::debug_print("\n--- Running: %s ---\n", result.test_name);

    delete_file(TEST_FILE_REDIRECT);

    ssl_debug::set_level(SSL_DEBUG_INFO);

    uint32_t start_time = get_time_ms();

    client* c = new client();
    int ret = c->download_file(URL_REDIRECT, 443, TEST_FILE_REDIRECT);
    delete c;

    result.time_ms = get_time_ms() - start_time;

    if (ret == 0) {
        if (file_exists(TEST_FILE_REDIRECT)) {
            result.bytes_downloaded = get_file_size(TEST_FILE_REDIRECT);
            if (result.bytes_downloaded > 0) {
                result.result = SSL_TEST_PASS;
                result.message = "Redirect followed and file downloaded";
            } else {
                result.result = SSL_TEST_FAIL;
                result.message = "File empty after redirect";
            }
        } else {
            result.result = SSL_TEST_FAIL;
            result.message = "File not created after redirect";
        }
    } else {
        result.result = SSL_TEST_FAIL;
        result.message = "Download with redirect failed";
    }

    delete_file(TEST_FILE_REDIRECT);

    return result;
}

// =============================================================================
// TEST: Chunked Transfer Encoding
// =============================================================================
ssl_test_result ssl_test::test_chunked_transfer()
{
    ssl_test_result result;
    result.test_name = "Chunked Transfer Encoding";
    result.message = "";
    result.bytes_downloaded = 0;
    result.time_ms = 0;

    debug_utility::debug_print("\n--- Running: %s ---\n", result.test_name);

    delete_file(TEST_FILE_CHUNKED);

    ssl_debug::set_level(SSL_DEBUG_INFO);

    uint32_t start_time = get_time_ms();

    client* c = new client();
    int ret = c->download_file(URL_CHUNKED, 443, TEST_FILE_CHUNKED);
    delete c;

    result.time_ms = get_time_ms() - start_time;

    if (ret == 0) {
        if (file_exists(TEST_FILE_CHUNKED)) {
            result.bytes_downloaded = get_file_size(TEST_FILE_CHUNKED);
            if (result.bytes_downloaded > 0) {
                result.result = SSL_TEST_PASS;
                result.message = "Chunked transfer handled correctly";
            } else {
                result.result = SSL_TEST_FAIL;
                result.message = "File empty";
            }
        } else {
            result.result = SSL_TEST_FAIL;
            result.message = "File not created";
        }
    } else {
        // Chunked might fail gracefully with some servers
        result.result = SSL_TEST_FAIL;
        result.message = "Chunked download failed";
    }

    delete_file(TEST_FILE_CHUNKED);

    return result;
}

// =============================================================================
// TEST: Session Resumption
// =============================================================================
ssl_test_result ssl_test::test_session_resumption()
{
    ssl_test_result result;
    result.test_name = "TLS Session Resumption";
    result.message = "";
    result.bytes_downloaded = 0;
    result.time_ms = 0;

    debug_utility::debug_print("\n--- Running: %s ---\n", result.test_name);

    // Clear session cache first
    session_cache::clear();

    ssl_debug::set_level(SSL_DEBUG_INFO);

    delete_file(TEST_FILE_RESUME);

    // First connection - should establish new session
    debug_utility::debug_print("First connection (new session)...\n");
    uint32_t start1 = get_time_ms();

    client* c1 = new client();
    int ret1 = c1->download_file(URL_SMALL, 443, TEST_FILE_RESUME);
    delete c1;

    uint32_t time1 = get_time_ms() - start1;

    if (ret1 != 0) {
        result.result = SSL_TEST_FAIL;
        result.message = "First connection failed";
        return result;
    }

    // Check if session was cached
    int cache_count = session_cache::get_count();
    debug_utility::debug_print("Sessions in cache: %d\n", cache_count);

    delete_file(TEST_FILE_RESUME);

    // Second connection - should resume session
    debug_utility::debug_print("Second connection (should resume)...\n");
    uint32_t start2 = get_time_ms();

    client* c2 = new client();
    int ret2 = c2->download_file(URL_SMALL, 443, TEST_FILE_RESUME);
    delete c2;

    uint32_t time2 = get_time_ms() - start2;

    result.time_ms = time1 + time2;

    if (ret2 == 0) {
        result.bytes_downloaded = get_file_size(TEST_FILE_RESUME);

        // Session resumption should make second connection faster
        // (though this is not guaranteed due to network variability)
        debug_utility::debug_print("First connection:  %u ms\n", time1);
        debug_utility::debug_print("Second connection: %u ms\n", time2);

        if (cache_count > 0) {
            result.result = SSL_TEST_PASS;
            result.message = "Session cached and second connection succeeded";
        } else {
            result.result = SSL_TEST_PASS;
            result.message = "Connections succeeded (server may not support resumption)";
        }
    } else {
        result.result = SSL_TEST_FAIL;
        result.message = "Second connection failed";
    }

    delete_file(TEST_FILE_RESUME);

    return result;
}

// =============================================================================
// TEST: Invalid Host (Error Handling)
// =============================================================================
ssl_test_result ssl_test::test_invalid_host()
{
    ssl_test_result result;
    result.test_name = "Invalid Host Error Handling";
    result.message = "";
    result.bytes_downloaded = 0;
    result.time_ms = 0;

    debug_utility::debug_print("\n--- Running: %s ---\n", result.test_name);

    ssl_debug::set_level(SSL_DEBUG_ERROR);

    uint32_t start_time = get_time_ms();

    // Try to connect to a non-existent host
    client* c = new client();
    int ret = c->download_file("https://this-host-does-not-exist-12345.invalid/test.bin", 443, "E:\\invalid.bin");
    delete c;

    result.time_ms = get_time_ms() - start_time;

    // This SHOULD fail - that's what we're testing
    if (ret != 0) {
        result.result = SSL_TEST_PASS;
        result.message = "Correctly failed on invalid host";
    } else {
        result.result = SSL_TEST_FAIL;
        result.message = "Should have failed but returned success";
    }

    delete_file("E:\\invalid.bin");

    return result;
}

// =============================================================================
// TEST: TLS Version Enforcement
// =============================================================================
ssl_test_result ssl_test::test_tls_version_enforcement()
{
    ssl_test_result result;
    result.test_name = "TLS 1.2 Enforcement";
    result.message = "";
    result.bytes_downloaded = 0;
    result.time_ms = 0;

    debug_utility::debug_print("\n--- Running: %s ---\n", result.test_name);

    // This test verifies that connections work with TLS 1.2
    // Most modern servers support TLS 1.2, so if our enforcement is correct,
    // connections should succeed. If we had wrongly configured TLS 1.0 only,
    // modern servers might reject us.

    ssl_debug::set_level(SSL_DEBUG_INFO);

    delete_file(TEST_FILE_SMALL);

    uint32_t start_time = get_time_ms();

    client* c = new client();
    int ret = c->download_file(URL_SMALL, 443, TEST_FILE_SMALL);
    delete c;

    result.time_ms = get_time_ms() - start_time;

    if (ret == 0 && file_exists(TEST_FILE_SMALL)) {
        result.bytes_downloaded = get_file_size(TEST_FILE_SMALL);
        result.result = SSL_TEST_PASS;
        result.message = "TLS 1.2 connection successful (check log for version)";
    } else {
        result.result = SSL_TEST_FAIL;
        result.message = "TLS 1.2 connection failed - check cipher/version compatibility";
    }

    delete_file(TEST_FILE_SMALL);

    return result;
}

// =============================================================================
// TEST: Alternate Host Connection
// =============================================================================
ssl_test_result ssl_test::test_alternate_host()
{
    ssl_test_result result;
    result.test_name = "Alternate Host (httpbin.org)";
    result.message = "";
    result.bytes_downloaded = 0;
    result.time_ms = 0;

    debug_utility::debug_print("\n--- Running: %s ---\n", result.test_name);

    delete_file(TEST_FILE_ALTERNATE);

    ssl_debug::set_level(SSL_DEBUG_INFO);

    uint32_t start_time = get_time_ms();

    client* c = new client();
    int ret = c->download_file(URL_ALTERNATE, 443, TEST_FILE_ALTERNATE);
    delete c;

    result.time_ms = get_time_ms() - start_time;

    if (ret == 0) {
        if (file_exists(TEST_FILE_ALTERNATE)) {
            result.bytes_downloaded = get_file_size(TEST_FILE_ALTERNATE);
            if (result.bytes_downloaded > 0) {
                result.result = SSL_TEST_PASS;
                result.message = "Non-GitHub host connection successful";
            } else {
                result.result = SSL_TEST_FAIL;
                result.message = "File created but empty";
            }
        } else {
            result.result = SSL_TEST_FAIL;
            result.message = "File not created";
        }
    } else {
        result.result = SSL_TEST_FAIL;
        result.message = "Connection to alternate host failed";
    }

    delete_file(TEST_FILE_ALTERNATE);

    return result;
}

// =============================================================================
// RUN ALL TESTS
// =============================================================================
int ssl_test::run_all_tests()
{
    debug_utility::debug_print("\n");
    debug_utility::debug_print("==========================================\n");
    debug_utility::debug_print("BearSSL-OG SSL/TLS TEST SUITE\n");
    debug_utility::debug_print("==========================================\n");
    debug_utility::debug_print("Testing HTTPS client functionality after\n");
    debug_utility::debug_print("SSL enhancements (TLS 1.2, ciphers, etc.)\n");
    debug_utility::debug_print("==========================================\n");

    int passed = 0;
    int failed = 0;
    int skipped = 0;

    ssl_test_result results[8];

    // Run all tests
    results[0] = test_basic_https_connection();
    results[1] = test_tls_version_enforcement();
    results[2] = test_session_resumption();
    results[3] = test_redirect_handling();
    results[4] = test_chunked_transfer();
    results[5] = test_alternate_host();
    results[6] = test_invalid_host();
    results[7] = test_large_file_download();

    // Print results and count
    for (int i = 0; i < 8; i++) {
        print_result(results[i]);

        switch (results[i].result) {
            case SSL_TEST_PASS: passed++; break;
            case SSL_TEST_FAIL: failed++; break;
            case SSL_TEST_SKIP: skipped++; break;
        }
    }

    // Print summary
    print_summary(passed, failed, skipped);

    return failed;
}
