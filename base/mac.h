#pragma once

#include <string>
#include "../eunet.h"

struct Mac {
    static constexpr int SIZE = 6;
    uint8_t mac_[SIZE];

    Mac() {}
    Mac(const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); }
    Mac(const unsigned char* r) { memcpy(this->mac_, r, SIZE); }
    Mac(const char* r) {
        sscanf(r, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_[0], &mac_[1], &mac_[2], &mac_[3], &mac_[4], &mac_[5]);
    }

    Mac& operator = (const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); return *this; }

    operator uint8_t*() { return mac_; }
    operator const uint8_t*() const { return mac_; }
    operator std::string() const {
        char buf[18];
        sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
        return std::string(buf);
    }

	// comparison operator
	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }
	bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) != 0; }
	bool operator < (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) < 0; }
	bool operator > (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) > 0; }
	bool operator <= (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) <= 0; }
	bool operator >= (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) >= 0; }
	bool operator == (const uint8_t* r) const { return memcmp(mac_, r, SIZE) == 0; }

    void clear() {
        for (int i = 0; i < SIZE; i++) mac_[i] = 0;
    }

    bool isNull() const {
        for (int i = 0; i < SIZE; i++) if (mac_[i] != 0) return false;
        return true;
    }

    bool isBroadcast() const {
        for (int i = 0; i < SIZE; i++) if (mac_[i] != 0xFF) return false;
        return true;
    }

    static Mac& nullMac();
    static Mac& broadcastMac();
};

// 외부에서 가져온 코드
Mac getMyMac(const char* interface_name);