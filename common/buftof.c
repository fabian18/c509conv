#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

ssize_t buftof(const void *buf, size_t size, const char *path)
{
    FILE *f;
    if (!(f = fopen(path, "w"))) {
        return -errno;
    }
    size_t wr;
    while (size) {
        if (!(wr = fwrite(buf, 1, size, f))) {
            return -EIO;
        }
        buf = ((unsigned char *)buf) + wr;
        size -= wr;
    }
    return fclose(f) ? -errno : size;
}
