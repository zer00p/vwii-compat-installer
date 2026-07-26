#pragma once

#include <stdint.h>

void ScreenUtils_ClearBuffer(uint32_t color);
void ScreenUtils_PutFont(uint32_t x, uint32_t y, const char *str);
void ScreenUtils_FlipBuffers();
void ScreenUtils_Enable();
