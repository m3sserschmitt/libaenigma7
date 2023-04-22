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
        ->useEncryption()
        ->noPlaintext()
        ->readKeyData(file, passphrase)
        ->build();
    }

    const unsigned char *AesGcmEncrypt(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        if (not ctx or not ctx->setPlaintext(plaintext, plaintextLen) or not ctx->run())
        {
            return nullptr;
        }

        const EncrypterData *ciphertext = ctx->getCiphertext();

        if (not ciphertext or ciphertext->isError())
        {
            return nullptr;
        }

        return ciphertext->getData();
    }

    const unsigned char *AesGcmDecrypt(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen)
    {
        if (not ctx or not ctx->setCiphertext(ciphertext, cipherLen) or not ctx->run())
        {
            return nullptr;
        }

        const EncrypterData *plaintext = ctx->getPlaintext();

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

    const unsigned char *RsaEncrypt(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen)
    {
        if (not ctx or not ctx->setPlaintext(plaintext, plaintextLen) or not ctx->run())
        {
            return nullptr;
        }

        const EncrypterData *ciphertext = ctx->getCiphertext();

        if (not ciphertext or ciphertext->isError())
        {
            return nullptr;
        }

        return ciphertext->getData();
    }

    const unsigned char *RsaDecrypt(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen)
    {
        if (not ctx or not ctx->setCiphertext(ciphertext, cipherLen) or not ctx->run())
        {
            return nullptr;
        }

        const EncrypterData *plaintext = ctx->getPlaintext();

        if (not plaintext or plaintext->isError())
        {
            return nullptr;
        }

        return plaintext->getData();
    }

    unsigned int GetRsaSize(unsigned int keySizeBits)
    {
        return keySizeBits / 8;
    }
}
