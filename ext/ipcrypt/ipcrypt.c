
#include "ipcrypt.h"

#define ROTL(X, R) (X) = (unsigned char) ((X) << (R)) | ((X) >> (8 - (R)))

static void
arx_fwd(unsigned char state[4])
{
    state[0] += state[1];
    state[2] += state[3];
    ROTL(state[1], 2);
    ROTL(state[3], 5);
    state[1] ^= state[0];
    state[3] ^= state[2];
    ROTL(state[0], 4);
    state[0] += state[3];
    state[2] += state[1];
    ROTL(state[1], 3);
    ROTL(state[3], 7);
    state[1] ^= state[2];
    state[3] ^= state[0];
    ROTL(state[2], 4);
}

static void
arx_bwd(unsigned char state[4])
{
    ROTL(state[2], 4);
    state[1] ^= state[2];
    state[3] ^= state[0];
    ROTL(state[1], 5);
    ROTL(state[3], 1);
    state[0] -= state[3];
    state[2] -= state[1];
    ROTL(state[0], 4);
    state[1] ^= state[0];
    state[3] ^= state[2];
    ROTL(state[1], 6);
    ROTL(state[3], 3);
    state[0] -= state[1];
    state[2] -= state[3];
}

static inline void
xor4(unsigned char *out, const unsigned char *x, const unsigned char *y)
{
    out[0] = x[0] ^ y[0];
    out[1] = x[1] ^ y[1];
    out[2] = x[2] ^ y[2];
    out[3] = x[3] ^ y[3];
}

int
ipcrypt_encrypt(unsigned char out[IPCRYPT_BYTES],
                const unsigned char in[IPCRYPT_BYTES],
                const unsigned char key[IPCRYPT_KEYBYTES])
{
    unsigned char state[4];

    xor4(state, in, key);
    arx_fwd(state);
    xor4(state, state, key + 4);
    arx_fwd(state);
    xor4(state, state, key + 8);
    arx_fwd(state);
    xor4(out, state, key + 12);

    return 0;
}

int
ipcrypt_decrypt(unsigned char out[IPCRYPT_BYTES],
                const unsigned char in[IPCRYPT_BYTES],
                const unsigned char key[IPCRYPT_KEYBYTES])
{
    unsigned char state[4];

    xor4(state, in, key + 12);
    arx_bwd(state);
    xor4(state, state, key + 8);
    arx_bwd(state);
    xor4(state, state, key + 4);
    arx_bwd(state);
    xor4(out, state, key);

    return 0;
}
