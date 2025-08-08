#pragma once

#include "../eunet.h"

struct Buf {
    size_t size_ = 0;
    const uint8_t* data_ = nullptr;
};