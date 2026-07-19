#pragma once

class State {
public:
    static void init();
    static bool AppRunning();
    static void shutdown();

    // Returns true once after the app re-acquires the foreground (e.g. after HOME menu).
    // Clears the flag after reading.
    static bool ForegroundReacquired();

private:
    static bool aroma;
    static bool wasBackground;
    static bool foregroundReacquired;
};