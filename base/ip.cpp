#include "ip.h"
#include <cstdlib> // for atoi

Ip::Ip(const string& r) {
    uint8_t* p = (uint8_t*)&ip_;
    int res = sscanf(r.c_str(), "%hhu.%hhu.%hhu.%hhu", &p[0], &p[1], &p[2], &p[3]);
    if (res != SIZE) {
        std::cerr << "sscanf failed, return " << res << std::endl;
        ip_ = 0;
        return;
    }
    ip_ = ntohl(ip_);
}

Ip::operator std::string() const {
    char s[INET_ADDRSTRLEN];
    sprintf(s, "%d.%d.%d.%d",
        (ip_ & 0xFF000000) >> 24,
        (ip_ & 0x00FF0000) >> 16,
        (ip_ & 0x0000FF00) >> 8,
        (ip_ & 0x000000FF) >> 0);
    return std::string(s);
}

// 외부에서 가져온 코드
Ip getMyIp(const char* interface_name) {
    int fd;
    struct ifreq ifr;
    struct sockaddr_in* addr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(1);
    }

    close(fd);
    addr = (struct sockaddr_in*)&ifr.ifr_addr;

    return Ip(addr->sin_addr.s_addr);
}