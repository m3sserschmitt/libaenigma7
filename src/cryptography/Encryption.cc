#include "cryptography/EncrypterResult.hh"
#include "cryptography/CryptoContext.hh"

extern "C"
{
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
}
