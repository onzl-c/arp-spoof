#include "ip.h"
#include <cstdlib> // for atoi

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
        perror("ioctl(SIOCGIFADDR)");
        close(fd);
        exit(1);
    }

    close(fd);
    addr = (struct sockaddr_in*)&ifr.ifr_addr;

    return Ip(addr->sin_addr.s_addr);
}