#pragma once

#include <vector>
#include <iostream>
#include <cstdint>
#include <pcap.h>
#include <netinet/in.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "base//ip.h"
#include "base/mac.h"
#include "base/buf.h"

using namespace std;