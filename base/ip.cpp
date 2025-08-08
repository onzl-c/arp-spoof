#include "ip.h"
#include <cstdlib> // for atoi

Ip::Ip(const string& r) {
    struct in_addr addr;
    if (inet_aton(r.c_str(), &addr) == 0) {
        fprintf(stderr, "Invalid IP address format: %s\n", r.c_str());
        ip_ = 0;
        return;
    }
    ip_ = addr.s_addr;
}

Ip::operator string() const {
    struct in_addr addr;
    addr.s_addr = ip_;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
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