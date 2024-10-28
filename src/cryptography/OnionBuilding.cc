#include <cstring>
#include <iostream>

#include "cryptography/Factories.hh"
#include "cryptography/Utils.hh"
#include "cryptography/Constants.hh"
#include "cryptography/Encryption.hh"

static bool sha256HexToBytes(const char *sha246Hex, unsigned char *out)
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

static void SealOnionRecursive(unsigned char *data, int &len, CryptoContext **ctx, const char **addresses, int i, unsigned int count)
{
    memcpy(data + ADDRESS_SIZE, data, len);
    if(!sha256HexToBytes(addresses[i], data))
    {
        len = -1;
        return;
    }

    const EncrypterResult *result = EncryptDataEx(ctx[i], data, len + ADDRESS_SIZE);

    if (result->isError())
    {
        len = -1;
        return;
    }

    int encryptionSize = result->getDataSize();
    len = encryptionSize + ONION_LENGTH_BYTES;

    memcpy(data + ONION_LENGTH_BYTES, result->getData(), encryptionSize);
    EncodeOnionSize(encryptionSize, data);

    if (i == count - 1)
    {
        return;
    }
    else
    {
        SealOnionRecursive(data, len, ctx, addresses, i + 1, count);
    }
}

static CryptoContext **AllocateStructuresAndCalculateTotalSize(unsigned int plaintextLen, const char **keys, const char **addresses, unsigned int count, int &allocatedIterations, unsigned char **outputBuffer)
{
    CryptoContext **ctx = new CryptoContext *[count];
    unsigned int requiredMemory = plaintextLen;

    for (allocatedIterations = 0; allocatedIterations < count; allocatedIterations++)
    {
        if (not keys[allocatedIterations] or not addresses[allocatedIterations] or
            not(ctx[allocatedIterations] = CreateAsymmetricEncryptionContext(keys[allocatedIterations])))
        {
            break;
        }

        requiredMemory = GetEnvelopeSize(requiredMemory + ADDRESS_SIZE, keys[allocatedIterations]) + ONION_LENGTH_BYTES;
    }

    if (allocatedIterations == count)
    {
        *outputBuffer = new unsigned char[requiredMemory + 1];
    }

    return ctx;
}

static void FreeStructures(CryptoContext **ctx, unsigned int allocatedIterations)
{
    for (int i = 0; i < allocatedIterations; i++)
    {
        FreeContext(ctx[i]);
    }

    delete[] ctx;
}

extern "C" const unsigned char *SealOnion(const unsigned char *plaintext, unsigned int plaintextLen, const char **keys, const char **addresses, unsigned int count, int &outLen)
{
    // required memory to hold the final onion
    unsigned char *output = nullptr;

    /*
     * keeps track of how many CryptoContext structures have been allocated;
     * there is a chance this number to be smaller than required, i.e. partial allocation (in case of invalid keys, for example);
     * we need to know how many have been allocated in order to release memory afterwards;
     */
    int allocatedIterations;

    CryptoContext **ctx = AllocateStructuresAndCalculateTotalSize(plaintextLen, keys, addresses, count, allocatedIterations, &output);
    outLen = -1;

    if (allocatedIterations == count)
    {
        memcpy(output, plaintext, plaintextLen);
        outLen = plaintextLen;

        SealOnionRecursive(output, outLen, ctx, addresses, 0, count);
    }

    FreeStructures(ctx, allocatedIterations);

    return output;
}
