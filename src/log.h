#pragma once

#include <stdio.h>

void WUPI_putstr(const char *str);
void WUPI_printTop();
void WUPI_resetScreen();
void WUPI_waitHome();
void WUPI_waitButton();

#define WUPI_Log(...) \
    do { \
        char _wupi_print_str[256]; \
        snprintf(_wupi_print_str, 255, __VA_ARGS__); \
        WUPI_putstr(_wupi_print_str); \
    } while (0)
