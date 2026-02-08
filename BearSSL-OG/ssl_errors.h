#pragma once

class ssl_errors
{
public:
    static const char* error_to_string(int error);
    static const char* alert_to_string(int alert_code);
};
