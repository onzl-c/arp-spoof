#pragma once

#include "../eunet.h"

struct Ip {
    static constexpr int SIZE = 4;
    uint32_t ip_;

    Ip() {}
    Ip(const Ip& r) : ip_(r.ip_) {}
    Ip(const uint32_t r) : ip_(r) {}
    Ip(const string& r);

    Ip& operator = (const Ip& r) { ip_ = r.ip_; return *this; }

    operator uint32_t() const { return ip_; } // default
    explicit operator string() const;
    
    void clear() {
        ip_ = 0;
    }

    bool isNull() const {
        return ip_ == 0;
    }

    bool isBroadcast() const {
        return (ip_ & 0xFF000000) == 0xE0000000;
    }
};

// 외부에서 가져온 코드
Ip getMyIp(const char* interface_name);