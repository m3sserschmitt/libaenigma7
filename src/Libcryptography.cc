#include "cryptography/Libcryptography.hh"
#include "cryptography/CryptoContextBuilder.hh"

extern "C"
{
    ICryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key)
    {
        return CryptoContextBuilder::Create()
            ->useAes()
            ->useEncryption()
            ->noPlaintext()
            ->setKey256(key)
            ->build();
    }

    ICryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key)
    {
        return CryptoContextBuilder::Create()
            ->useAes()
            ->useDecryption()
            ->noCiphertext()
            ->setKey256(key)
            ->build();
    }

    ICryptoContext *CreateAsymmetricDecryptionContext(const char *key, char *passphrase)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useDecryption()
            ->noCiphertext()
            ->setKey(key, passphrase)
            ->build();
    }

    ICryptoContext *CreateAsymmetricEncryptionContext(const char *key)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useEncryption()
            ->noPlaintext()
            ->setKey(key)
            ->build();
    }

    ICryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useEncryption()
            ->noPlaintext()
            ->readKeyData(path)
            ->build();
    }

    ICryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *file, char *passphrase)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useDecryption()
            ->noCiphertext()
            ->readKeyData(file, passphrase)
            ->build();
    }

    ICryptoContext *CreateSignatureContext(const char *key, char *passphrase)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useSignature()
            ->noPlaintext()
            ->setKey(key, passphrase)
            ->build();
    }

    ICryptoContext *CreateVerificationContext(const char *key)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useSignatureVerification()
            ->noCiphertext()
            ->setKey(key)
            ->build();
    }

    ICryptoContext *CreateSignatureContextFromFile(const char *path, char *passphrase)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useSignature()
            ->noPlaintext()
            ->readKeyData(path, passphrase)
            ->build();
    }

    ICryptoContext *CreateVerificationContextFromFile(const char *path)
    {
        return CryptoContextBuilder::Create()
            ->useRsa()
            ->useSignatureVerification()
            ->noCiphertext()
            ->readKeyData(path)
            ->build();
    }

    void FreeContext(ICryptoContext *context)
    {
        delete context;
    }

    const EncrypterData *encrypt(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        if (not ctx or not ctx->setPlaintext(plaintext, plaintextLen) or not ctx->run())
        {
            return nullptr;
        }

        return ctx->getCiphertext();
    }

    const unsigned char *EncryptData(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        const EncrypterData *ciphertext = encrypt(ctx, plaintext, plaintextLen);

        if (not ciphertext or ciphertext->isError())
        {
            return nullptr;
        }

        return ciphertext->getData();
    }

    const EncrypterData *decrypt(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen)
    {
        if (not ctx or not ctx->setCiphertext(ciphertext, cipherLen) or not ctx->run())
        {
            return nullptr;
        }

        return ctx->getPlaintext();
    }

    const unsigned char *DecryptData(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen)
    {
        const EncrypterData *plaintext = decrypt(ctx, ciphertext, cipherLen);

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

    const unsigned char *SignData(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        return EncryptData(ctx, plaintext, plaintextLen);
    }

    bool VerifySignature(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen)
    {
        const EncrypterData *plaintext = decrypt(ctx, ciphertext, cipherLen);

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
