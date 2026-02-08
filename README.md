# XboxCurl — libcurl + BearSSL for Original Xbox

A simple port of **libcurl 7.65.3** with **BearSSL 0.6** for the **Original Xbox**, plus a small on-console test program to verify networking, HTTP, and HTTPS/TLS features on real hardware.

This project is mainly for Xbox homebrew developers who want working HTTP/HTTPS support using libcurl on the OG Xbox.

## Credits

### Current Project
- **libcurl + BearSSL integration, updates, and test suite**  
  Extended by Applesauceman (2026)

### Based On
- **Original libcurl Xbox port** — Team Resurgent & Crunchbite  
  https://github.com/Team-Resurgent/libcurl-Update  

- **Original BearSSL Xbox port** — Team Resurgent  
  https://github.com/Team-Resurgent/BearSSL-OG


---

## What is libcurl?

**libcurl** is a widely used networking library that lets programs transfer data using protocols like:

- HTTP / HTTPS
- FTP
- and more (depending on build)

It handles:
- connections
- DNS
- redirects
- uploads & downloads
- headers
- authentication
- TLS/SSL

It’s used in thousands of projects (including browsers, package managers, and game tools).

---

## What is BearSSL?

**BearSSL** is a small, efficient SSL/TLS library designed for constrained systems.

In this port it provides:
- HTTPS support
- TLS handshakes
- encryption
- certificate handling
- session reuse (faster reconnects)

It was chosen because it fits well within Original Xbox memory and CPU limits.

---

## What This Project Provides

- libcurl **7.65.3 ported to Original Xbox**
- BearSSL **0.6 integrated for HTTPS**
- Xbox-compatible networking using **XNet**
- A simple **test suite app** that runs on the console
- Debug output via **XBDM**

---

<img width="1164" height="655" alt="image" src="https://github.com/user-attachments/assets/9f913ae7-b28e-4f6d-9409-5342c215320f" />
<img width="1164" height="655" alt="image" src="https://github.com/user-attachments/assets/f331d030-feba-48a4-9fe6-158340a9f93d" />



## Features Tested

The included test program checks that libcurl works correctly on Xbox:

### Networking
- Ethernet + DHCP startup
- DNS resolution
- Raw TCP connection to port 443

### HTTP
- GET / POST
- Custom headers
- User-Agent
- Redirect handling
- Timeouts
- Large downloads

### HTTPS / TLS
- HTTPS GET
- TLS handshake
- Optional certificate verification
- TLS version testing
- Session resumption (faster reconnects)

### Upload / Download
- Multipart file upload
- PUT / DELETE / PATCH
- Download to `T:\` (E:\TDATA\00000000) drive
- Range requests (partial download)

### Security Features
- TLS session cache
- Certificate pinning API (basic)

---

## Debug Output

The test app shows:

**On screen**
- PASS / FAIL / SKIP per test
- HTTP codes, bytes, timing

**In XBDM debug log**
- Full HTTP request headers
- TLS handshake messages
- SSL record debug (for troubleshooting)

---

## Building (General)

This project targets the **Original Xbox XDK environment**.

Typical steps:

1. Build **libcurl + BearSSL** for Xbox (static libraries).
2. Link them into an Xbox title project.
3. Run the included test program on hardware or devkit.

(Exact steps depend on your XDK / build setup.)

---

## Requirements

- Original Xbox
- Working Ethernet connection (DHCP)
- XBDM recommended for debug output

---

## Test Program

When run, the test app:

1. Initializes graphics + console
2. Starts network and waits for DHCP
3. Runs HTTP and HTTPS tests
4. Prints a summary (passed / failed / skipped)
5. Stays running so results remain visible

---

## Notes

- Some HTTPS verification tests may **skip** if a CA bundle is not configured.
- Uses public endpoints like `httpbin.org` for testing.
- Files are downloaded to `T:\` (E:\TDATA\00000000) during file tests.

---

## License

This project includes:

- libcurl (libcurl license)
- BearSSL (BearSSL license)

See upstream projects for full license details.

---

## Purpose

This repo is mainly for:

- Bringing modern-ish HTTP/HTTPS to Original Xbox homebrew
- Testing TLS behavior on real hardware
- Providing a base for Xbox apps that need web/network features

