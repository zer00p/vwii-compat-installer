#include "ScreenUtils.h"
#include <coreinit/screen.h>

void ScreenUtils_ClearBuffer(uint32_t color) {
    OSScreenClearBufferEx(SCREEN_TV, color);
    OSScreenClearBufferEx(SCREEN_DRC, color);
}

void ScreenUtils_PutFont(uint32_t x, uint32_t y, const char *str) {
    OSScreenPutFontEx(SCREEN_TV, x, y, str);
    OSScreenPutFontEx(SCREEN_DRC, x, y, str);
}

void ScreenUtils_FlipBuffers() {
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);
}

void ScreenUtils_Enable() {
    OSScreenEnableEx(SCREEN_TV, 1);
    OSScreenEnableEx(SCREEN_DRC, 1);
}
