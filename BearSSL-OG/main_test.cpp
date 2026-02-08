// main_test.cpp - Test runner for SSL enhancements
//
// This is an alternative main() that runs the SSL test suite instead of
// the normal server/client operations. To use:
//
// Option 1: Rename this to main.cpp (backup original first)
// Option 2: Add a #define RUN_SSL_TESTS before including this
// Option 3: Copy the test call into your existing main.cpp
//
// Example usage in existing main.cpp:
//
//   #include "ssl_test.h"
//
//   void __cdecl main()
//   {
//       // ... network init code ...
//
//       // Run SSL tests
//       int failures = ssl_test::run_all_tests();
//
//       if (failures > 0) {
//           debug_utility::debug_print("SSL tests had %d failures\n", failures);
//       }
//
//       // ... rest of your code ...
//   }

#include "stdafx.h"

#include "network_utility.h"
#include "client.h"
#include "server.h"
#include "debug_utility.h"
#include "ssl_test.h"
#include "ssl_debug.h"

bool mount_e_drive()
{
    char* mountPoint = "\\??\\E:";
    char* systemPath = "\\Device\\Harddisk0\\Partition1";
    STRING sMountPoint = {(USHORT)strlen(mountPoint), (USHORT)strlen(mountPoint) + 1, mountPoint};
    STRING sSystemPath = {(USHORT)strlen(systemPath), (USHORT)strlen(systemPath) + 1, systemPath};
    int result = IoCreateSymbolicLink(&sMountPoint, &sSystemPath);
    return result == 0;
}

void __cdecl main()
{
    debug_utility::debug_print("BearSSL-OG Test Runner\n");
    debug_utility::debug_print("======================\n\n");

    // Initialize network
    debug_utility::debug_print("Initializing network...\n");
    if (network_utility::init() == false)
    {
        debug_utility::debug_print("ERROR: Network init failed\n");
        return;
    }

    debug_utility::debug_print("Waiting for network ready...\n");
    if (network_utility::wait_ready() == false)
    {
        debug_utility::debug_print("ERROR: Network not ready\n");
        return;
    }

    debug_utility::debug_print("Network ready!\n");

    // Mount E: drive for test files
    if (mount_e_drive())
    {
        debug_utility::debug_print("E: drive mounted\n");
    }
    else
    {
        debug_utility::debug_print("WARNING: E: drive mount failed\n");
    }

    // Set default debug level
    ssl_debug::set_level(SSL_DEBUG_INFO);

    // =========================================================================
    // RUN SSL TEST SUITE
    // =========================================================================
    int failures = ssl_test::run_all_tests();

    // =========================================================================
    // OPTIONAL: Run individual tests
    // =========================================================================
    // Uncomment any of these to run specific tests:
    //
    // ssl_test_result r1 = ssl_test::test_basic_https_connection();
    // ssl_test::print_result(r1);
    //
    // ssl_test_result r2 = ssl_test::test_large_file_download();
    // ssl_test::print_result(r2);
    //
    // ssl_test_result r3 = ssl_test::test_session_resumption();
    // ssl_test::print_result(r3);

    // =========================================================================
    // OPTIONAL: Quick single download test
    // =========================================================================
    // If you just want to test a single download:
    //
    // client* c = new client();
    // int result = c->download_file(
    //     "https://raw.githubusercontent.com/AbanteAI/rawdog/main/README.md",
    //     443,
    //     "E:\\test_download.txt"
    // );
    // debug_utility::debug_print("Download result: %d\n", result);
    // delete c;

    // Report final status
    debug_utility::debug_print("\n\n");
    if (failures == 0)
    {
        debug_utility::debug_print("*** ALL SSL TESTS PASSED ***\n");
    }
    else
    {
        debug_utility::debug_print("*** %d SSL TEST(S) FAILED ***\n", failures);
    }

    // Keep alive so output can be read
    debug_utility::debug_print("\nTest complete. System will idle.\n");
    while (true)
    {
        Sleep(1000);
    }
}
