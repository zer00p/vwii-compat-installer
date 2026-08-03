#include "ScreenUtils.h"
#include "StateUtils.h"
#include <coreinit/screen.h>
#include <cstring>

/* Shadow buffer: records what was drawn so it can be replayed on resume. */
#define SHADOW_MAX_ROWS 18
#define SHADOW_MAX_COLS 128

static struct {
    uint32_t clearColor;
    struct {
        uint32_t x;
        char text[SHADOW_MAX_COLS];
    } lines[SHADOW_MAX_ROWS];
} s_Shadow;

void ScreenUtils_ClearBuffer(uint32_t color) {
    if (State::isExiting()) return;
    s_Shadow.clearColor = color;
    for (int i = 0; i < SHADOW_MAX_ROWS; i++)
        s_Shadow.lines[i].text[0] = '\0';
    OSScreenClearBufferEx(SCREEN_TV, color);
    OSScreenClearBufferEx(SCREEN_DRC, color);
}

void ScreenUtils_PutFont(uint32_t x, uint32_t y, const char *str) {
    if (State::isExiting()) return;
    if (y < SHADOW_MAX_ROWS) {
        s_Shadow.lines[y].x = x;
        strncpy(s_Shadow.lines[y].text, str, SHADOW_MAX_COLS - 1);
        s_Shadow.lines[y].text[SHADOW_MAX_COLS - 1] = '\0';
    }
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

void ScreenUtils_ClearBothBuffers() {
    ScreenUtils_ClearBuffer(0);
    ScreenUtils_FlipBuffers();
    ScreenUtils_ClearBuffer(0);
    ScreenUtils_FlipBuffers();
}

void ScreenUtils_Redraw() {
    if (State::isExiting()) return;
    /* Replay the shadow to both back-buffers (raw calls to avoid re-recording). */
    for (int pass = 0; pass < 2; pass++) {
        OSScreenClearBufferEx(SCREEN_TV, s_Shadow.clearColor);
        OSScreenClearBufferEx(SCREEN_DRC, s_Shadow.clearColor);
        for (int i = 0; i < SHADOW_MAX_ROWS; i++) {
            if (s_Shadow.lines[i].text[0] != '\0') {
                OSScreenPutFontEx(SCREEN_TV, s_Shadow.lines[i].x, i, s_Shadow.lines[i].text);
                OSScreenPutFontEx(SCREEN_DRC, s_Shadow.lines[i].x, i, s_Shadow.lines[i].text);
            }
        }
        OSScreenFlipBuffersEx(SCREEN_TV);
        OSScreenFlipBuffersEx(SCREEN_DRC);
    }
}

void ScreenUtils_ScrollUp() {
    if (State::isExiting()) return;
    for (int i = 1; i < SHADOW_MAX_ROWS; i++) {
        s_Shadow.lines[i - 1].x = s_Shadow.lines[i].x;
        strncpy(s_Shadow.lines[i - 1].text, s_Shadow.lines[i].text, SHADOW_MAX_COLS);
    }
    s_Shadow.lines[SHADOW_MAX_ROWS - 1].text[0] = '\0';
    ScreenUtils_Redraw();
}
