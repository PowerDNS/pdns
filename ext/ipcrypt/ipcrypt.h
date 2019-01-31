
#ifndef ipcrypt_H
#define ipcrypt_H

#define IPCRYPT_BYTES 4
#define IPCRYPT_KEYBYTES 16

#ifdef __cplusplus
extern "C" {
#endif

int ipcrypt_encrypt(unsigned char out[IPCRYPT_BYTES],
                    const unsigned char in[IPCRYPT_BYTES],
                    const unsigned char key[IPCRYPT_KEYBYTES]);

int ipcrypt_decrypt(unsigned char out[IPCRYPT_BYTES],
                    const unsigned char in[IPCRYPT_BYTES],
                    const unsigned char key[IPCRYPT_KEYBYTES]);

#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif

#endif
