#include "mac.h"

Mac::Mac(const std::string& r) {
    std::string s;
    for (char ch : r) {
        if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F'|| (ch >= 'a' && ch <= 'f')))
            s += ch;
    }
    int res = sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                    &mac_[0], &mac_[1], &mac_[2], &mac_[3], &mac_[4], &mac_[5]);
    if (res != SIZE) {
        std::cerr << "sscanf failed, return " << res << std::endl;
        memset(mac_, 0, SIZE);
    }
}

Mac::operator std::string() const {
    char s[20];
    sprintf(s, "%02X:%02X:%02X:%02X:%02X:%02X", 
            mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
    return std::string(s);
}

Mac::operator uint64_t() const {
    uint64_t res = 0;
    for (int i = 0; i < SIZE; i++) {
        res = (res << 8) | mac_[i];
    }
    return res;
}

Mac& Mac::nullMac() {
    static uint8_t _value[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static Mac res(_value);
    return res;
}

Mac& Mac::broadcastMac() {
    static uint8_t _value[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    static Mac res(_value);
    return res;
}

// 외부에서 가져온 코드
Mac getMyMac(const char* interface_name) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return Mac::nullMac();
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return Mac::nullMac();
    }
    close(sock);
    
    Mac myMac;
    memcpy(myMac.mac_, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    return myMac;
}