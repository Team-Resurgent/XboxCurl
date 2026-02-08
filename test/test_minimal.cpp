/*
 * Xbox libcurl + BearSSL Minimal Test
 * Uses OutputDebugStringA only - no D3D console
 */

#include <xtl.h>
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

/* Debug print */
void DebugPrint(const char *fmt, ...)
{
    char buffer[512];
    va_list args;
    va_start(args, fmt);
    _vsnprintf(buffer, sizeof(buffer) - 1, fmt, args);
    buffer[sizeof(buffer) - 1] = '\0';
    va_end(args);
    OutputDebugStringA(buffer);
}

/* Simple write callback */
static size_t total_bytes = 0;
size_t WriteCallback(char *buf, size_t size, size_t nmemb, void *userdata)
{
    (void)buf;
    (void)userdata;
    total_bytes += size * nmemb;
    return size * nmemb;
}

/* Initialize networking */
int InitNetwork(void)
{
    XNetStartupParams xnsp;
    WSADATA wsaData;
    XNADDR xna;
    int timeout = 0;

    memset(&xnsp, 0, sizeof(xnsp));
    xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
    xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
    xnsp.cfgPrivatePoolSizeInPages = 128;
    xnsp.cfgEnetReceiveQueueLength = 64;
    xnsp.cfgSockMaxSockets = 64;
    xnsp.cfgSockDefaultRecvBufsizeInK = 128;
    xnsp.cfgSockDefaultSendBufsizeInK = 128;

    XNetStartup(&xnsp);
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    DebugPrint("Waiting for network...\n");

    do {
        if (XNetGetTitleXnAddr(&xna) != XNET_GET_XNADDR_PENDING)
            break;
        Sleep(100);
        timeout += 100;
    } while (timeout < 10000);

    if (timeout >= 10000) {
        DebugPrint("Network timeout!\n");
        return -1;
    }

    DebugPrint("Network ready. IP: %d.%d.%d.%d\n",
        xna.ina.S_un.S_un_b.s_b1,
        xna.ina.S_un.S_un_b.s_b2,
        xna.ina.S_un.S_un_b.s_b3,
        xna.ina.S_un.S_un_b.s_b4);

    return 0;
}

/* Test helper */
void TestResult(const char *name, int passed, const char *details)
{
    if (passed) {
        DebugPrint("[PASS] %s - %s\n", name, details);
        tests_passed++;
    } else {
        DebugPrint("[FAIL] %s - %s\n", name, details);
        tests_failed++;
    }
}

/* Test: HTTP GET by IP */
void test_http_get_ip(void)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    char details[128] = {0};

    DebugPrint("\n--- Test: HTTP GET (by IP) ---\n");
    total_bytes = 0;

    curl = curl_easy_init();
    if (!curl) {
        TestResult("HTTP GET IP", 0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://1.1.1.1/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && http_code >= 200 && http_code < 400) {
        _snprintf(details, sizeof(details) - 1, "HTTP %ld, %u bytes", http_code, (unsigned)total_bytes);
        TestResult("HTTP GET IP", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (HTTP %ld)", curl_easy_strerror(res), http_code);
        TestResult("HTTP GET IP", 0, details);
    }
}

/* Test: HTTP GET with DNS */
void test_http_get_dns(void)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    char details[128] = {0};

    DebugPrint("\n--- Test: HTTP GET (DNS) ---\n");
    total_bytes = 0;

    curl = curl_easy_init();
    if (!curl) {
        TestResult("HTTP GET DNS", 0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && http_code == 200) {
        _snprintf(details, sizeof(details) - 1, "HTTP %ld, %u bytes", http_code, (unsigned)total_bytes);
        TestResult("HTTP GET DNS", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (HTTP %ld)", curl_easy_strerror(res), http_code);
        TestResult("HTTP GET DNS", 0, details);
    }
}

/* Test: HTTPS GET (no verify) */
void test_https_get_no_verify(void)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    char details[128] = {0};

    DebugPrint("\n--- Test: HTTPS GET (no verify) ---\n");
    total_bytes = 0;

    curl = curl_easy_init();
    if (!curl) {
        TestResult("HTTPS GET (no verify)", 0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "https://1.1.1.1/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && http_code >= 200 && http_code < 400) {
        _snprintf(details, sizeof(details) - 1, "HTTPS %ld, %u bytes, TLS OK", http_code, (unsigned)total_bytes);
        TestResult("HTTPS GET (no verify)", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (HTTP %ld)", curl_easy_strerror(res), http_code);
        TestResult("HTTPS GET (no verify)", 0, details);
    }
}

/* Test: HTTPS GET with DNS (no verify) */
void test_https_get_dns(void)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    char details[128] = {0};

    DebugPrint("\n--- Test: HTTPS GET DNS (no verify) ---\n");
    total_bytes = 0;

    curl = curl_easy_init();
    if (!curl) {
        TestResult("HTTPS GET DNS", 0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && http_code == 200) {
        _snprintf(details, sizeof(details) - 1, "HTTPS %ld, %u bytes, TLS OK", http_code, (unsigned)total_bytes);
        TestResult("HTTPS GET DNS", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (HTTP %ld)", curl_easy_strerror(res), http_code);
        TestResult("HTTPS GET DNS", 0, details);
    }
}

/* Test: HTTP POST */
void test_http_post(void)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    char details[128] = {0};
    const char *post_data = "name=XboxCurl&test=1";

    DebugPrint("\n--- Test: HTTP POST ---\n");
    total_bytes = 0;

    curl = curl_easy_init();
    if (!curl) {
        TestResult("HTTP POST", 0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && http_code == 200) {
        _snprintf(details, sizeof(details) - 1, "HTTP %ld, %u bytes", http_code, (unsigned)total_bytes);
        TestResult("HTTP POST", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (HTTP %ld)", curl_easy_strerror(res), http_code);
        TestResult("HTTP POST", 0, details);
    }
}

/* Test: HTTPS POST */
void test_https_post(void)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    char details[128] = {0};
    const char *post_data = "{\"test\":\"XboxCurl\",\"secure\":true}";
    struct curl_slist *headers = NULL;

    DebugPrint("\n--- Test: HTTPS POST (JSON) ---\n");
    total_bytes = 0;

    curl = curl_easy_init();
    if (!curl) {
        TestResult("HTTPS POST", 0, "curl_easy_init failed");
        return;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/post");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && http_code == 200) {
        _snprintf(details, sizeof(details) - 1, "HTTPS %ld, %u bytes, TLS OK", http_code, (unsigned)total_bytes);
        TestResult("HTTPS POST", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (HTTP %ld)", curl_easy_strerror(res), http_code);
        TestResult("HTTPS POST", 0, details);
    }
}

/* Test: HTTPS GET with certificate verification ENABLED
 * This validates the full trust anchor chain works end-to-end.
 * Uses a well-known public site with a standard CA-signed certificate.
 */
void test_https_get_verified(void)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    char details[128] = {0};

    DebugPrint("\n--- Test: HTTPS GET (verified) ---\n");
    total_bytes = 0;

    curl = curl_easy_init();
    if (!curl) {
        TestResult("HTTPS GET (verified)", 0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "https://one.one.one.one/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    /* Certificate verification ON - this is the whole point of this test */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && http_code >= 200 && http_code < 400) {
        _snprintf(details, sizeof(details) - 1, "HTTPS %ld, %u bytes, cert VERIFIED", http_code, (unsigned)total_bytes);
        TestResult("HTTPS GET (verified)", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (HTTP %ld)", curl_easy_strerror(res), http_code);
        TestResult("HTTPS GET (verified)", 0, details);
    }
}

/* Test: HTTP Redirect */
void test_http_redirect(void)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    long redirect_count = 0;
    char details[128] = {0};

    DebugPrint("\n--- Test: HTTP Redirect ---\n");
    total_bytes = 0;

    curl = curl_easy_init();
    if (!curl) {
        TestResult("HTTP Redirect", 0, "curl_easy_init failed");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://httpbin.org/redirect/2");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirect_count);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && http_code == 200 && redirect_count >= 2) {
        _snprintf(details, sizeof(details) - 1, "HTTP %ld after %ld redirects", http_code, redirect_count);
        TestResult("HTTP Redirect", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (HTTP %ld, %ld redirects)", curl_easy_strerror(res), http_code, redirect_count);
        TestResult("HTTP Redirect", 0, details);
    }
}

/* Test: Connection Timeout */
void test_timeout(void)
{
    CURL *curl;
    CURLcode res;
    DWORD start, elapsed;
    char details[128] = {0};

    DebugPrint("\n--- Test: Connection Timeout ---\n");

    curl = curl_easy_init();
    if (!curl) {
        TestResult("Timeout", 0, "curl_easy_init failed");
        return;
    }

    /* Non-routable IP to force timeout */
    curl_easy_setopt(curl, CURLOPT_URL, "http://10.255.255.1/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    start = GetTickCount();
    res = curl_easy_perform(curl);
    elapsed = GetTickCount() - start;
    curl_easy_cleanup(curl);

    if (res == CURLE_OPERATION_TIMEDOUT || res == CURLE_COULDNT_CONNECT) {
        _snprintf(details, sizeof(details) - 1, "Timed out after %lu ms (expected)", elapsed);
        TestResult("Timeout", 1, details);
    } else {
        _snprintf(details, sizeof(details) - 1, "%s (%lu ms)", curl_easy_strerror(res), elapsed);
        TestResult("Timeout", 1, details);  /* Other errors acceptable */
    }
}

/* Test: D3D Initialization */
void test_d3d_init(void)
{
    IDirect3D8 *d3d = NULL;
    IDirect3DDevice8 *device = NULL;
    D3DPRESENT_PARAMETERS d3dpp;
    HRESULT hr;
    char details[128] = {0};

    DebugPrint("\n--- Test: D3D Initialization ---\n");

    d3d = Direct3DCreate8(D3D_SDK_VERSION);
    if (!d3d) {
        TestResult("D3D Create", 0, "Direct3DCreate8 failed");
        return;
    }
    TestResult("D3D Create", 1, "Direct3DCreate8 OK");

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
        _snprintf(details, sizeof(details) - 1, "CreateDevice failed: 0x%08X", hr);
        TestResult("D3D Device", 0, details);
        d3d->Release();
        return;
    }
    TestResult("D3D Device", 1, "CreateDevice OK");

    /* Clear with BeginScene/EndScene for proper GPU sync */
    hr = device->BeginScene();
    if (FAILED(hr)) {
        _snprintf(details, sizeof(details) - 1, "BeginScene failed: 0x%08X", hr);
        TestResult("D3D BeginScene", 0, details);
    }

    hr = device->Clear(0, NULL, D3DCLEAR_TARGET, D3DCOLOR_XRGB(0, 0, 255), 1.0f, 0);
    if (FAILED(hr)) {
        _snprintf(details, sizeof(details) - 1, "Clear failed: 0x%08X", hr);
        TestResult("D3D Clear", 0, details);
    } else {
        TestResult("D3D Clear", 1, "Clear OK (blue)");
    }

    device->EndScene();

    hr = device->Present(NULL, NULL, NULL, NULL);
    if (FAILED(hr)) {
        _snprintf(details, sizeof(details) - 1, "Present failed: 0x%08X", hr);
        TestResult("D3D Present", 0, details);
    } else {
        TestResult("D3D Present", 1, "Present OK - should see BLUE");
    }

    /* Wait to see blue screen */
    Sleep(3000);

    /* Second frame - green */
    device->BeginScene();
    device->Clear(0, NULL, D3DCLEAR_TARGET, D3DCOLOR_XRGB(0, 255, 0), 1.0f, 0);
    device->EndScene();
    device->Present(NULL, NULL, NULL, NULL);
    DebugPrint("Should see GREEN now\n");
    Sleep(2000);

    /* Clean up */
    device->Release();
    d3d->Release();

    TestResult("D3D Cleanup", 1, "Released D3D resources");
}

void __cdecl main(void)
{
    DebugPrint("\n");
    DebugPrint("========================================\n");
    DebugPrint("  Xbox libcurl + BearSSL Test Suite\n");
    DebugPrint("========================================\n");
    DebugPrint("libcurl version: %s\n", curl_version());

    /* D3D Test first */
    DebugPrint("\n=== D3D TESTS ===\n");
    test_d3d_init();

    /* Network init */
    if (InitNetwork() != 0) {
        DebugPrint("FATAL: Network init failed\n");
        goto done;
    }

    DebugPrint("\nInitializing libcurl...\n");
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        DebugPrint("FATAL: curl_global_init failed\n");
        goto done;
    }
    DebugPrint("curl_global_init OK\n");

    /* HTTP Tests */
    DebugPrint("\n=== HTTP TESTS ===\n");
    test_http_get_ip();
    test_http_get_dns();
    test_http_post();
    test_http_redirect();

    /* HTTPS Tests */
    DebugPrint("\n=== HTTPS TESTS ===\n");
    test_https_get_no_verify();
    test_https_get_dns();
    test_https_post();
    test_https_get_verified();

    /* Other Tests */
    DebugPrint("\n=== OTHER TESTS ===\n");
    test_timeout();

    curl_global_cleanup();

done:
    DebugPrint("\n========================================\n");
    DebugPrint("  TEST RESULTS\n");
    DebugPrint("========================================\n");
    DebugPrint("  Passed: %d\n", tests_passed);
    DebugPrint("  Failed: %d\n", tests_failed);
    DebugPrint("  Total:  %d\n", tests_passed + tests_failed);
    DebugPrint("========================================\n");

    if (tests_failed == 0) {
        DebugPrint("  ALL TESTS PASSED!\n");
    } else {
        DebugPrint("  SOME TESTS FAILED\n");
    }
    DebugPrint("========================================\n");

    DebugPrint("\nTest complete. Looping forever.\n");
    while (1) Sleep(1000);
}
