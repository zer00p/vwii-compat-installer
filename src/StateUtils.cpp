#include "StateUtils.h"
#include "ScreenUtils.h"
#include <coreinit/core.h>
#include <coreinit/dynload.h>
#include <coreinit/foreground.h>
#include <coreinit/screen.h>
#include <proc_ui/procui.h>
#include <whb/proc.h>

bool State::aroma = false;
bool State::wasBackground = false;
bool State::foregroundReacquired = false;

void State::init() {
    OSDynLoad_Module mod;
    aroma = OSDynLoad_Acquire("homebrew_kernel", &mod) == OS_DYNLOAD_OK;
    if (aroma) {
        OSDynLoad_Release(mod);
        ProcUIInit(&OSSavesDone_ReadyToRelease);
        OSEnableHomeButtonMenu(true);
    } else
        WHBProcInit();
}

bool State::AppRunning() {
    if (aroma) {
        bool app = true;
        if (OSIsMainCore()) {
            switch (ProcUIProcessMessages(true)) {
                case PROCUI_STATUS_EXITING:
                    // Being closed, prepare to exit
                    app = false;
                    break;
                case PROCUI_STATUS_RELEASE_FOREGROUND:
                    // Free up MEM1 to next foreground app, deinit screen, etc.
                    ProcUIDrawDoneRelease();
                    wasBackground = true;
                    break;
                case PROCUI_STATUS_IN_FOREGROUND:
                    // Re-enable screens after returning from background
                    if (wasBackground) {
                        ScreenUtils_Enable();
                        foregroundReacquired = true;
                        wasBackground = false;
                    }
                    app = true;
                    break;
                case PROCUI_STATUS_IN_BACKGROUND:
                    wasBackground = true;
                    OSSleepTicks(OSMillisecondsToTicks(20));
                    break;
            }
        }

        return app;
    }
    return WHBProcIsRunning();
}

bool State::ForegroundReacquired() {
    if (foregroundReacquired) {
        foregroundReacquired = false;
        return true;
    }
    return false;
}

void State::shutdown() {
    if (aroma) {
        // Do NOT call OSScreenShutdown() here. Under Aroma, the system has
        // already reclaimed foreground memory (MEM1) by the time we reach this
        // point, so any access to screen hardware will crash (invalid access
        // in OSScreenEnableEx called internally by OSScreenShutdown).
        ProcUIShutdown();
    } else {
        OSScreenShutdown();
        WHBProcShutdown();
        // Note: WHBProcIsRunning() already called ProcUIShutdown() when the
        // main loop exited, so we must NOT call it again here.
    }
}