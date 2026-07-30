#include "log.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include "InputUtils.h"
#include <string.h>
#include <unistd.h>

static int32_t wupiLine = 0;
static const int32_t WUPI_MAX_LINES = 28;

static void wupiPrintln(int32_t line, const char *str) {
    /* put line twice for double buffer */
    ScreenUtils_PutFont(0, line, str);
    ScreenUtils_FlipBuffers();

    ScreenUtils_PutFont(0, line, str);
    ScreenUtils_FlipBuffers();
}

void WUPI_printTop() {
}

void WUPI_putstr(const char *str) {
    if (wupiLine >= WUPI_MAX_LINES)
        wupiLine = WUPI_MAX_LINES - 1;
    wupiPrintln(wupiLine++, str);
}

void WUPI_putstr_overwrite(const char *str) {
    if (wupiLine > 0) {
        ScreenUtils_PutFont(0, wupiLine - 1, str);
        ScreenUtils_Redraw();
    } else {
        wupiPrintln(wupiLine++, str);
    }
}

void WUPI_resetScreen() {
    ScreenUtils_ClearBothBuffers();
    wupiLine = 0;

    WUPI_printTop();
}


void WUPI_waitButton() {
    WUPI_putstr("Press ANY button to return to menu, or HOME to exit.");
    Input input;
    while (State::AppRunning()) {
        input.read();
        if (input.get(TRIGGER, PAD_BUTTON_ANY)) {
            return;
        }
    }
}

