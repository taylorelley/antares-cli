#include <string.h>
#include <stdlib.h>
void copy(char *dst, const char *src) {
    char *buf = malloc(64);
    strcpy(buf, src);
    memcpy(dst, buf, 64);
    free(buf);
}
