#include "log.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include "InputUtils.h"
#include <string.h>

static int32_t wupiLine = 4;

static void wupiPrintln(int32_t line, const char *str) {
    /* put line twice for double buffer */
    ScreenUtils_PutFont(0, line, str);
    ScreenUtils_FlipBuffers();

    ScreenUtils_PutFont(0, line, str);
    ScreenUtils_FlipBuffers();
}

void WUPI_printTop() {
    wupiPrintln(0, "Compat Title Installer v1.6");
    wupiPrintln(1, "COPYRIGHT (c) 2021-2023 TheLordScruffy, DaThinkingChair");
}

void WUPI_putstr(const char *str) {
    wupiPrintln(wupiLine++, str);
}

void WUPI_resetScreen() {
    ScreenUtils_ClearBuffer(0);
    ScreenUtils_FlipBuffers();
    ScreenUtils_ClearBuffer(0);
    ScreenUtils_FlipBuffers();
    wupiLine = 4;

    WUPI_printTop();
}

void WUPI_waitHome() {
    WUPI_putstr("Press HOME to exit.");
    while (State::AppRunning()) {
        if (State::ForegroundReacquired()) {
            WUPI_resetScreen();
            WUPI_putstr("Press HOME to exit.");
        }
    }
    return;
}

void WUPI_waitButton() {
    WUPI_putstr("Press ANY button to return to menu, or HOME to exit.");
    Input input;
    while (State::AppRunning()) {
        if (State::ForegroundReacquired()) {
            WUPI_resetScreen();
            WUPI_putstr("Press ANY button to return to menu, or HOME to exit.");
        }

        input.read();
        if (input.get(TRIGGER, PAD_BUTTON_ANY)) {
            return;
        }
    }
}
