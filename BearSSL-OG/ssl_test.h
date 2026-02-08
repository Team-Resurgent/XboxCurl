#pragma once

#include <stdint.h>

// Test result codes
#define SSL_TEST_PASS       0
#define SSL_TEST_FAIL       1
#define SSL_TEST_SKIP       2

// Test result structure
struct ssl_test_result {
    const char* test_name;
    int result;
    const char* message;
    int64_t bytes_downloaded;
    uint32_t time_ms;
};

class ssl_test
{
public:
    // Run all tests and print summary
    static int run_all_tests();

    // Individual tests
    static ssl_test_result test_basic_https_connection();
    static ssl_test_result test_large_file_download();
    static ssl_test_result test_redirect_handling();
    static ssl_test_result test_chunked_transfer();
    static ssl_test_result test_session_resumption();
    static ssl_test_result test_invalid_host();
    static ssl_test_result test_tls_version_enforcement();
    static ssl_test_result test_alternate_host();

    // Utility
    static void print_result(const ssl_test_result& result);
    static void print_summary(int passed, int failed, int skipped);

private:
    static uint32_t get_time_ms();
    static bool file_exists(const char* path);
    static int64_t get_file_size(const char* path);
    static void delete_file(const char* path);
};
