#include "ScreenUtils.h"
#include "StateUtils.h"
#include <coreinit/screen.h>

void ScreenUtils_ClearBuffer(uint32_t color) {
    if (State::isExiting()) return;
    OSScreenClearBufferEx(SCREEN_TV, color);
    OSScreenClearBufferEx(SCREEN_DRC, color);
}

void ScreenUtils_PutFont(uint32_t x, uint32_t y, const char *str) {
    if (State::isExiting()) return;
    OSScreenPutFontEx(SCREEN_TV, x, y, str);
    OSScreenPutFontEx(SCREEN_DRC, x, y, str);
}

void ScreenUtils_FlipBuffers() {
    if (State::isExiting()) return;
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);
}

void ScreenUtils_Enable() {
    if (State::isExiting()) return;
    OSScreenEnableEx(SCREEN_TV, 1);
    OSScreenEnableEx(SCREEN_DRC, 1);
}
