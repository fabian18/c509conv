#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

ssize_t ftobuf(void *buf, size_t size, const char *path)
{
    int r = 0;
    FILE *f;
    if (!(f = fopen(path, "r"))) {
        return -errno;
    }
    size_t size_cpy = size;
    size_t rd;
    while (size) {
        if ((rd = fread(buf, 1, size, f)) > 0) {
            buf = ((unsigned char *)buf) + rd;
            size -= rd;
        }
        if (feof(f) || (r = ferror(f))) {
            break;
        }
    };
    fclose(f);
    return r ? -EIO : (ssize_t)(size_cpy - size);
}
