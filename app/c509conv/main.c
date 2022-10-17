#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <buftof.h>
#include <ftobuf.h>
#include <c509.h>

#ifndef BUFSIZE
#define BUFSIZE (1024u * 8)
#endif

#define CSTRLEN(s) (sizeof(((const char[]){s})) - 1)

static inline int _cpy(void *dst, size_t dst_size, const void *src, size_t src_size)
{
    if (dst_size < src_size) {
        return -ENOBUFS;
    }
    memcpy(dst, src, src_size);
    return src_size;
}

static inline void _usage(const char *program)
{
    printf("%s <input.[der | cbor]> <output.[der | cbor]>\n", program);
}

int main(int argc, char *argv[]) {
    int ret = EXIT_FAILURE;
    uint8_t *inbuf = NULL;
    uint8_t *outbuf = NULL;

    if (argc != 3) {
        _usage(argv[0]);
        goto EXIT;
    }
    if (!(inbuf = calloc(BUFSIZE, 1))) {
        goto EXIT;
    }
    if (!(outbuf = calloc(BUFSIZE, 1))) {
        goto EXIT;
    }

    int (*conv_function)(void *, size_t, const void *, size_t) = NULL;

    {
        size_t len;
        if ((len = strlen(argv[1])) &&
            (len > CSTRLEN(".der")) &&
            (memcmp(argv[1] + len - CSTRLEN(".der"), ".der", CSTRLEN(".der"))) == 0) {

            if ((len = strlen(argv[2])) &&
                (len > CSTRLEN(".cbor")) &&
                (memcmp(argv[2] + len - CSTRLEN(".cbor"), ".cbor", CSTRLEN(".cbor"))) == 0) {

                conv_function = x509_to_c509;
            }
            else if ((len = strlen(argv[2])) &&
                    (len > CSTRLEN(".der")) &&
                    (memcmp(argv[2] + len - CSTRLEN(".der"), ".der", CSTRLEN(".der"))) == 0) {

                conv_function = _cpy;
            }
        }
        else if ((len = strlen(argv[1])) &&
                (len > CSTRLEN(".cbor")) &&
                (memcmp(argv[1] + len - CSTRLEN(".cbor"), ".cbor", CSTRLEN(".cbor"))) == 0) {

            if ((len = strlen(argv[2])) &&
                (len > CSTRLEN(".der")) &&
                (memcmp(argv[2] + len - CSTRLEN(".der"), ".der", CSTRLEN(".der"))) == 0) {

                conv_function = c509_to_x509;
            }
            else if ((len = strlen(argv[2])) &&
                    (len > CSTRLEN(".cbor")) &&
                    (memcmp(argv[2] + len - CSTRLEN(".cbor"), ".cbor", CSTRLEN(".cbor"))) == 0) {

                conv_function = _cpy;
            }
        }
    }
    if (!conv_function) {
        fprintf(stderr, "Certificate format not supported\n");
        _usage(argv[0]);
        goto EXIT;
    }
    if ((ftobuf(inbuf, BUFSIZE, argv[1])) < 0){
        fprintf(stderr, "Cannot read input: %s\n", argv[1]);
        goto EXIT;
    }
    int len;
    if ((len = conv_function(outbuf, BUFSIZE, inbuf, BUFSIZ)) < 0) {
        fprintf(stderr, "Conversion failed\n");
        goto EXIT;
    }
    if ((buftof(outbuf, len, argv[2])) < 0) {
        fprintf(stderr, "Cannot write output: %s\n", argv[2]);
        goto EXIT;
    }
    ret = EXIT_SUCCESS;
EXIT:
    free(inbuf);
    free(outbuf);
    exit(ret);
}
