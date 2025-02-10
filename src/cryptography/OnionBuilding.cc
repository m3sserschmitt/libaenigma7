#include <cstring>
#include <iostream>

#include "cryptography/Factories.hh"
#include "cryptography/Utils.hh"
#include "cryptography/Constants.hh"
#include "cryptography/Encryption.hh"

static bool Sha256HexToBytes(const char *sha246Hex, unsigned char *out)
{
    try
    {
        unsigned int stringSize = 2 * ADDRESS_SIZE;
        if (strlen(sha246Hex) != stringSize)
        {
            return false;
        }

        char buffer[3]{0};

        for (int i = 0; i < stringSize; i += 2)
        {
            memcpy(buffer, sha246Hex + i, 2);
            out[i / 2] = static_cast<unsigned char>(std::stoi(buffer, nullptr, 16));
        }

        return true;
    }
    catch (const std::exception &e)
    {
        return false;
    }
}

static void EncodeOnionSize(unsigned int size, unsigned char *out)
{
    out[0] = size / 256;
    out[1] = size % 256;
}

static int GetOnionSize(unsigned int plaintextLen, const char *key)
{
    int envelopeSize = GetEnvelopeSize(plaintextLen + ADDRESS_SIZE, key);
    return envelopeSize < 0 ? -1 : envelopeSize + ONION_LENGTH_BYTES;
}

static bool Seal(const unsigned char *in, unsigned int inlen, const char *key, const char *address, unsigned char *out, int &outlen)
{
    CryptoContext *ctx = nullptr;
    outlen = -1;

    if(!key || !address || !(ctx = CreateAsymmetricEncryptionContext(key)))
    {
        return false;
    }

    if(!Sha256HexToBytes(address, out))
    {
        FreeContext(ctx);
        return false;
    }
    memcpy(out + ADDRESS_SIZE, in, inlen);

    const EncrypterResult *result = EncryptDataEx(ctx, out, inlen + ADDRESS_SIZE);

    if (result->isError())
    {
        FreeContext(ctx);
        return false;
    }

    outlen = result->getDataSize() + ONION_LENGTH_BYTES;
    memcpy(out + ONION_LENGTH_BYTES, result->getData(), result->getDataSize());
    EncodeOnionSize(result->getDataSize(), out);

    FreeContext(ctx);
    return true;
}

extern "C" const unsigned char *SealOnion(const unsigned char *plaintext, unsigned int plaintextLen, const char **keys, const char **addresses, unsigned int count, int &outlen)
{
    unsigned char *out = nullptr;
    for(int i = 0; i < count; i ++)
    {
        int onionSize = GetOnionSize(plaintextLen, keys[i]);

        if(onionSize < 0 || !addresses[i])
        {
            i > 0 ? delete[] plaintext : void();
            outlen = -1;
            return nullptr;
        }

        out = new unsigned char[onionSize];

        if(!Seal(plaintext, plaintextLen, keys[i], addresses[i], out, outlen) || outlen < 0)
        {
            delete[] out;
            i > 0 ? delete[] plaintext : void();
            outlen = -1;
            return nullptr;
        }

        i > 0 ? delete[] plaintext : void();
        plaintext = out;
        plaintextLen = outlen;
    }

    return out;
}
