#include "ssl_errors.h"
#include <bearssl.h>

const char* ssl_errors::error_to_string(int error)
{
    switch (error) {
        case BR_ERR_OK: return "Success";
        case BR_ERR_BAD_PARAM: return "Bad parameter";
        case BR_ERR_BAD_STATE: return "Invalid state";
        case BR_ERR_UNSUPPORTED_VERSION: return "Unsupported TLS version";
        case BR_ERR_BAD_VERSION: return "Bad TLS version";
        case BR_ERR_TOO_LARGE: return "Record too large";
        case BR_ERR_BAD_MAC: return "MAC verification failed";
        case BR_ERR_NO_RANDOM: return "No random seed";
        case BR_ERR_UNKNOWN_TYPE: return "Unknown record type";
        case BR_ERR_UNEXPECTED: return "Unexpected message";
        case BR_ERR_BAD_CCS: return "Bad ChangeCipherSpec";
        case BR_ERR_BAD_ALERT: return "Bad alert";
        case BR_ERR_BAD_HANDSHAKE: return "Bad handshake message";
        case BR_ERR_OVERSIZED_ID: return "Oversized ID";
        case BR_ERR_BAD_CIPHER_SUITE: return "Bad cipher suite";
        case BR_ERR_BAD_COMPRESSION: return "Bad compression";
        case BR_ERR_BAD_FRAGLEN: return "Bad fragment length";
        case BR_ERR_BAD_SECRENEG: return "Bad secure renegotiation";
        case BR_ERR_EXTRA_EXTENSION: return "Extra extension";
        case BR_ERR_BAD_SNI: return "Bad SNI";
        case BR_ERR_BAD_HELLO_DONE: return "Bad HelloDone";
        case BR_ERR_LIMIT_EXCEEDED: return "Limit exceeded";
        case BR_ERR_BAD_FINISHED: return "Bad Finished message";
        case BR_ERR_RESUME_MISMATCH: return "Session resume mismatch";
        case BR_ERR_INVALID_ALGORITHM: return "Invalid algorithm";
        case BR_ERR_BAD_SIGNATURE: return "Bad signature";
        case BR_ERR_WRONG_KEY_USAGE: return "Wrong key usage";
        case BR_ERR_NO_CLIENT_AUTH: return "No client auth";
        case BR_ERR_IO: return "I/O error";
        default:
            if (error >= 256 && error < 512)
                return "Received fatal alert from server";
            if (error >= 512)
                return "Sent fatal alert to server";
            return "Unknown SSL error";
    }
}

const char* ssl_errors::alert_to_string(int alert_code)
{
    switch (alert_code) {
        case 0: return "close_notify";
        case 10: return "unexpected_message";
        case 20: return "bad_record_mac";
        case 21: return "decryption_failed";
        case 22: return "record_overflow";
        case 30: return "decompression_failure";
        case 40: return "handshake_failure";
        case 42: return "bad_certificate";
        case 43: return "unsupported_certificate";
        case 44: return "certificate_revoked";
        case 45: return "certificate_expired";
        case 46: return "certificate_unknown";
        case 47: return "illegal_parameter";
        case 48: return "unknown_ca";
        case 49: return "access_denied";
        case 50: return "decode_error";
        case 51: return "decrypt_error";
        case 70: return "protocol_version";
        case 71: return "insufficient_security";
        case 80: return "internal_error";
        case 90: return "user_canceled";
        case 100: return "no_renegotiation";
        case 110: return "unsupported_extension";
        default: return "unknown_alert";
    }
}
