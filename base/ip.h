#pragma once

#include "../eunet.h"

struct Ip {
    static constexpr int SIZE = 4;
    uint32_t ip_;

    Ip() {}
    Ip(const Ip& r) : ip_(r.ip_) {}
    Ip(const uint32_t r) : ip_(r) {}
    Ip(const string& r) {
        struct in_addr addr;
        if (inet_aton(r.c_str(), &addr) == 0) {
            fprintf(stderr, "Invalid IP format: %s\n", r.c_str());
            ip_ = 0;
            return;
        }
        ip_ = addr.s_addr;
    }

    Ip& operator = (const Ip& r) { ip_ = r.ip_; return *this; }

    operator uint32_t() const { return ip_; } // default
    operator std::string() const {
        struct in_addr addr;
        addr.s_addr = ip_;
        return std::string(inet_ntoa(addr));
    }
    
    void clear() {
        ip_ = 0;
    }

    bool isNull() const {
        return ip_ == 0;
    }

    bool isBroadcast() const {
        return ip_ == 0xFFFFFFFF;
    }
};

// 외부에서 가져온 코드
Ip getMyIp(const char* interface_name);