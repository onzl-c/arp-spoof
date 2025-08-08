#pragma once

#include "../eunet.h"

struct Mac {
    static constexpr int SIZE = 6;
    uint8_t mac_[SIZE];

    Mac() {}
    Mac(const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); }
    Mac(const unsigned char* r) { memcpy(this->mac_, r, SIZE); }
    Mac(const string& r);
    Mac(const uint64_t& r);

    Mac& operator = (const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); return *this; }

    explicit operator string() const;
    explicit operator uint64_t() const;

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