#include "cryptography/Encryption.hh"
#include "cryptography/Constants.hh"

#include <pthread.h>

extern "C"
{
    unsigned int DecodeOnionSize(const unsigned char *onion)
    {
        if (not onion)
        {
            return 0;
        }

        unsigned int size = 0;
        for (int i = 0; i < ONION_LENGTH_BYTES; i++)
        {
            size += onion[i] * pow(256, ONION_LENGTH_BYTES - i - 1);
        }

        return size;
    }

    const unsigned char *UnsealOnion(CryptoContext *ctx, const unsigned char *onion, int &plaintextLen)
    {
        plaintextLen = 0;
        if (not onion or not ctx)
        {
            return nullptr;
        }

        const unsigned char *ciphertext = onion + ONION_LENGTH_BYTES;
        unsigned int cipherLen = DecodeOnionSize(onion);

        return DecryptData(ctx, ciphertext, cipherLen, plaintextLen);
    }
}
