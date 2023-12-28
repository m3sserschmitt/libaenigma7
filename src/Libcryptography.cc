#include "cryptography/Libcryptography.hh"
#include "cryptography/CryptoContextBuilder.hh"

extern "C"
{
    CryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useAes()
                                     ->useEncryption()
                                     ->noPlaintext()
                                     ->setKey256(key)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useAes()
                                     ->useDecryption()
                                     ->noCiphertext()
                                     ->setKey256(key)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateAsymmetricDecryptionContext(const char *key, const char *passphrase)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useDecryption()
                                     ->noCiphertext()
                                     ->setKey(key, passphrase)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateAsymmetricEncryptionContext(const char *key)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useEncryption()
                                     ->noPlaintext()
                                     ->setKey(key)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useEncryption()
                                     ->noPlaintext()
                                     ->readKeyData(path)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *file, const char *passphrase)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useDecryption()
                                     ->noCiphertext()
                                     ->readKeyData(file, passphrase)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateSignatureContext(const char *key, const char *passphrase)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useSignature()
                                     ->noPlaintext()
                                     ->setKey(key, passphrase)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateVerificationContext(const char *key)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useSignatureVerification()
                                     ->noCiphertext()
                                     ->setKey(key)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateSignatureContextFromFile(const char *path, const char *passphrase)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useSignature()
                                     ->noPlaintext()
                                     ->readKeyData(path, passphrase)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateVerificationContextFromFile(const char *path)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useSignatureVerification()
                                     ->noCiphertext()
                                     ->readKeyData(path)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    void FreeContext(CryptoContext *context)
    {
        delete context;
    }

    const EncrypterResult *EncryptDataEx(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        if (not ctx or not ctx->setPlaintext(plaintext, plaintextLen) or not ctx->run())
        {
            return nullptr;
        }

        return ctx->getCiphertext();
    }

    const unsigned char *EncryptData(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen, int &cipherLen)
    {
        const EncrypterData *ciphertext = EncryptDataEx(ctx, plaintext, plaintextLen);

        if (not ciphertext or ciphertext->isError())
        {
            cipherLen = -1;
            return nullptr;
        }

        cipherLen = ciphertext->getDataSize();
        return ciphertext->getData();
    }

    const EncrypterResult *DecryptDataEx(CryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen)
    {
        if (not ctx or not ctx->setCiphertext(ciphertext, cipherLen) or not ctx->run())
        {
            return nullptr;
        }

        return ctx->getPlaintext();
    }

    const unsigned char *DecryptData(CryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen, int &plaintextLen)
    {
        const EncrypterData *plaintext = DecryptDataEx(ctx, ciphertext, cipherLen);

        if (not plaintext or plaintext->isError())
        {
            plaintextLen = -1;
            return nullptr;
        }

        plaintextLen = plaintext->getDataSize();
        return plaintext->getData();
    }

    unsigned int GetAesGcmCiphertextSize(unsigned int plaintext)
    {
        return plaintext + IV_SIZE + TAG_SIZE;
    }

    unsigned int GetAesGcmPlaintextSize(unsigned int ciphertext)
    {
        return ciphertext - TAG_SIZE - IV_SIZE;
    }

    const unsigned char *SignData(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen, int &signatureLen)
    {
        return EncryptData(ctx, plaintext, plaintextLen, signatureLen);
    }

    const EncrypterResult *SignDataEx(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        return EncryptDataEx(ctx, plaintext, plaintextLen);
    }

    bool VerifySignature(CryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen)
    {
        const EncrypterData *plaintext = DecryptDataEx(ctx, ciphertext, cipherLen);

        return plaintext != nullptr and not plaintext->isError();
    }

    unsigned int GetEnvelopeSize(unsigned int pkeySizeBits, unsigned int plaintextLen)
    {
        return pkeySizeBits / 8 + IV_SIZE + TAG_SIZE + plaintextLen;
    }

    unsigned int GetOpenEnvelopeSize(unsigned int pkeySizeBits, unsigned int envelopeSize)
    {
        return envelopeSize - pkeySizeBits / 8 - IV_SIZE - TAG_SIZE;
    }

    unsigned int GetSignedDataSize(unsigned int pkeySizeBits, unsigned int dataSize)
    {
        return pkeySizeBits / 8 + dataSize;
    }
}
