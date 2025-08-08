#include "mac.h"

Mac::operator std::string() const {
    char buf[18];
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
    return std::string(buf);
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