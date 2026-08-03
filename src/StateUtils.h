#pragma once

class State {
public:
    static void init();
    static bool AppRunning();
    static void shutdown();

    static bool isExiting();

private:
    static bool aroma;
    static bool wasBackground;
    static bool exiting;
};