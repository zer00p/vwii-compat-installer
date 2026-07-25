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
bool State::exiting = false;

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
    if (exiting) return false;

    if (aroma) {
        if (!OSIsMainCore()) return true;

        while (true) {
            switch (ProcUIProcessMessages(true)) {
                case PROCUI_STATUS_EXITING:
                    // Being closed, prepare to exit
                    exiting = true;
                    return false;
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
                    return true;
                case PROCUI_STATUS_IN_BACKGROUND:
                    wasBackground = true;
                    OSSleepTicks(OSMillisecondsToTicks(20));
                    break;
                default:
                    break;
            }
        }
    }
    bool running = WHBProcIsRunning();
    if (!running) {
        exiting = true;
    }
    return running;
}

bool State::ForegroundReacquired() {
    if (foregroundReacquired) {
        foregroundReacquired = false;
        return true;
    }
    return false;
}

bool State::isExiting() {
    return exiting;
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