#include "cryptography/Aenigma.hh"
#include "cryptography/PublicKey.hh"
#include "cryptography/CryptoContextBuilder.hh"
#include <cmath>

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

static bool Seal(const unsigned char *in, unsigned int inLen, const char *key, const char *address, unsigned char *out, int &outLen)
{
    CryptoContext *ctx = nullptr;
    outLen = -1;

    if (!key || !address || !(ctx = CreateAsymmetricEncryptionContext(key)))
    {
        return false;
    }

    if (!Sha256HexToBytes(address, out))
    {
        FreeContext(ctx);
        return false;
    }
    memcpy(out + ADDRESS_SIZE, in, inLen);

    const EncrypterResult *result = RunEx(ctx, out, inLen + ADDRESS_SIZE);

    if (result->isError())
    {
        FreeContext(ctx);
        return false;
    }

    outLen = (int)result->getDataSize() + ONION_LENGTH_BYTES;
    memcpy(out + ONION_LENGTH_BYTES, result->getData(), result->getDataSize());
    EncodeOnionSize(result->getDataSize(), out);

    FreeContext(ctx);
    return true;
}

#ifndef __ANDROID__
extern "C" bool SetMasterPassphraseName(const char *name)
{
    return PrivateKey::setMasterPassphraseName(name, strnlen(name, MASTER_PASSPHRASE_MAX_NAME_SIZE));
}

extern "C" int CreateMasterPassphrase(const char *passphrase)
{
    return PrivateKey::createMasterPassphrase(passphrase, strnlen(passphrase, MAX_KERNEL_KEY_SIZE));
}

extern "C" bool RemoveMasterPassphrase()
{
    return PrivateKey::removeMasterPassphrase();
}

#endif

extern "C" CryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useAes()
                             ->useEncryption()
                             ->setKey(key)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useAes()
                             ->useDecryption()
                             ->setKey(key)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateAsymmetricDecryptionContext(const char *key, const char *passphrase)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useRsa()
                             ->useUnsealing()
                             ->setKey(key, passphrase)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateAsymmetricEncryptionContext(const char *key)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useRsa()
                             ->useSealing()
                             ->setKey(key)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();

    CryptoContext *ctx = builder->useRsa()
                             ->useSealing()
                             ->readKeyData(path)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *file, const char *passphrase)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useRsa()
                             ->useUnsealing()
                             ->readKeyData(file, passphrase)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateSignatureContext(const char *key, const char *passphrase)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useRsa()
                             ->useSignature()
                             ->setKey(key, passphrase)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateVerificationContext(const char *key)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useRsa()
                             ->useSignatureVerification()
                             ->setKey(key)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateSignatureContextFromFile(const char *path, const char *passphrase)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useRsa()
                             ->useSignature()
                             ->readKeyData(path, passphrase)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" CryptoContext *CreateVerificationContextFromFile(const char *path)
{
    ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
    CryptoContext *ctx = builder->useRsa()
                             ->useSignatureVerification()
                             ->readKeyData(path)
                             ->build();
    delete builder;
    return ctx;
}

extern "C" void FreeContext(CryptoContext *context)
{
    delete context;
}

extern "C" const EncrypterResult *RunEx(CryptoContext *ctx, const unsigned char *in, unsigned int inLen)
{
    if (not ctx or not ctx->setInput(in, inLen) or not ctx->run())
    {
        return nullptr;
    }

    return ctx->getOutput();
}

extern "C" const unsigned char *Run(CryptoContext *ctx, const unsigned char *in, unsigned int inLen, int &outLen)
{
    const EncrypterData *ciphertext = RunEx(ctx, in, inLen);

    if (not ciphertext or ciphertext->isError())
    {
        outLen = -1;
        return nullptr;
    }

    outLen = (int)ciphertext->getDataSize();
    return ciphertext->getData();
}

extern "C" bool RunVerification(CryptoContext *ctx, const unsigned char *in, unsigned int inLen)
{
    const EncrypterData *plaintext = RunEx(ctx, in, inLen);

    return plaintext != nullptr and not plaintext->isError();
}

extern "C" unsigned int DecodeOnionSize(const unsigned char *onion)
{
    if (not onion)
    {
        return 0;
    }

    unsigned int size = 0;
    for (int i = 0; i < ONION_LENGTH_BYTES; i++)
    {
        size += (unsigned int)onion[i] * (unsigned int)pow(256, ONION_LENGTH_BYTES - i - 1);
    }

    return size;
}

extern "C" const unsigned char *UnsealOnion(CryptoContext *ctx, const unsigned char *onion, int &plaintextLen)
{
    plaintextLen = -1;
    if (not onion or not ctx)
    {
        return nullptr;
    }

    const unsigned char *ciphertext = onion + ONION_LENGTH_BYTES;
    unsigned int cipherLen = DecodeOnionSize(onion);

    return Run(ctx, ciphertext, cipherLen, plaintextLen);
}

extern "C" const unsigned char *SealOnion(const unsigned char *plaintext, unsigned int plaintextLen, const char **keys, const char **addresses, unsigned int count, int &outLen)
{
    unsigned char *out = nullptr;
    for (int i = 0; i < count; i++)
    {
        int onionSize = GetOnionSize(plaintextLen, keys[i]);

        if (onionSize < 0 || !addresses[i])
        {
            i > 0 ? delete[] plaintext : void();
            outLen = -1;
            return nullptr;
        }

        out = new unsigned char[onionSize];

        if (!Seal(plaintext, plaintextLen, keys[i], addresses[i], out, outLen) || outLen < 0)
        {
            delete[] out;
            i > 0 ? delete[] plaintext : void();
            outLen = -1;
            return nullptr;
        }

        i > 0 ? delete[] plaintext : void();
        plaintext = out;
        plaintextLen = outLen;
    }

    return out;
}

extern "C" unsigned int GetAesGcmCiphertextSize(unsigned int plaintext)
{
    return plaintext + IV_SIZE + TAG_SIZE;
}

extern "C" int GetAesGcmPlaintextSize(unsigned int ciphertext)
{
    return (int)ciphertext - TAG_SIZE - IV_SIZE;
}

extern "C" int GetPKeySize(const char *publicKey)
{
    if (!publicKey)
    {
        return -1;
    }

    Key *key = new PublicKey();
    key->setKeyData((const unsigned char *)publicKey, strlen(publicKey), nullptr);

    int keySize = key->getSize();
    delete key;

    return keySize;
}

extern "C" int GetEnvelopeSize(unsigned int plaintextLen, const char *publicKey)
{
    int pKeySize = GetPKeySize(publicKey);
    return pKeySize < 0 ? -1 : pKeySize + IV_SIZE + TAG_SIZE + (int)plaintextLen;
}

extern "C" int GetOpenEnvelopeSize(unsigned int envelopeSize, const char *publicKey)
{
    int pKeySize = GetPKeySize(publicKey);
    return pKeySize < 0 ? -1 : (int)envelopeSize - pKeySize - IV_SIZE - TAG_SIZE;
}

extern "C" int GetSignedDataSize(unsigned int dataSize, const char *publicKey)
{
    int pKeySize = GetPKeySize(publicKey);
    return pKeySize < 0 ? -1 : pKeySize + (int)dataSize;
}

extern "C" int GetAddressSize()
{
    return ADDRESS_SIZE;
}

extern "C" int GetKernelKeyMaxSize()
{
    return MAX_KERNEL_KEY_SIZE;
}
