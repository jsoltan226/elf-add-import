#include <stdio.h>
#include <stdarg.h>

extern __attribute__((visibility("default")))
int printf(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    int ret = vprintf(fmt, vlist);
    va_end(vlist);

    puts("<< sus :) >>");
    return ret;
}

extern __attribute__((visibility("default")))
void sus_test(void)
{
    puts("sus test :)");
}
