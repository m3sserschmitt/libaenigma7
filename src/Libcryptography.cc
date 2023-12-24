#include "cryptography/Libcryptography.hh"
#include "cryptography/CryptoContextBuilder.hh"

extern "C"
{
    CryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key)
    {
        return CryptoContextBuilder::Create()
            ->useAes()
            ->useEncryption()
            ->noPlaintext()
            ->setKey256(key)
            ->build();
    }

    CryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key)
    {
        return CryptoContextBuilder::Create()
            ->useAes()
            ->useDecryption()
            ->noCiphertext()
            ->setKey256(key)
            ->build();
    }

    CryptoContext *CreateAsymmetricDecryptionContext(const char *key, char *passphrase)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useDecryption()
            ->noCiphertext()
            ->setKey(key, passphrase)
            ->build();
    }

    CryptoContext *CreateAsymmetricEncryptionContext(const char *key)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useEncryption()
            ->noPlaintext()
            ->setKey(key)
            ->build();
    }

    CryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useEncryption()
            ->noPlaintext()
            ->readKeyData(path)
            ->build();
    }

    CryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *file, char *passphrase)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useDecryption()
            ->noCiphertext()
            ->readKeyData(file, passphrase)
            ->build();
    }

    CryptoContext *CreateSignatureContext(const char *key, char *passphrase)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useSignature()
            ->noPlaintext()
            ->setKey(key, passphrase)
            ->build();
    }

    CryptoContext *CreateVerificationContext(const char *key)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useSignatureVerification()
            ->noCiphertext()
            ->setKey(key)
            ->build();
    }

    CryptoContext *CreateSignatureContextFromFile(const char *path, char *passphrase)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useSignature()
            ->noPlaintext()
            ->readKeyData(path, passphrase)
            ->build();
    }

    CryptoContext *CreateVerificationContextFromFile(const char *path)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useSignatureVerification()
            ->noCiphertext()
            ->readKeyData(path)
            ->build();
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

    const unsigned char *EncryptData(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        const EncrypterData *ciphertext = EncryptDataEx(ctx, plaintext, plaintextLen);

        if (not ciphertext or ciphertext->isError())
        {
            return nullptr;
        }

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

    const unsigned char *DecryptData(CryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen)
    {
        const EncrypterData *plaintext = DecryptDataEx(ctx, ciphertext, cipherLen);

        if (not plaintext or plaintext->isError())
        {
            return nullptr;
        }

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

    const unsigned char *SignData(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        return EncryptData(ctx, plaintext, plaintextLen);
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
}
