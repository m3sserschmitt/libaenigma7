#ifndef CRYPTO_CONTEXT_BUILDER_HH
#define CRYPTO_CONTEXT_BUILDER_HH

#include <exception>

#include "contracts/ICryptoContextBuilderType.hh"
#include "CryptoContext.hh"

class CryptoContextBuilder
{
private:
    class Impl
        : public ICryptoContextBuilderType,
          public ICryptoContextBuilderRsaOperation,
          public ICryptoContextBuilderPlaintext,
          public ICryptoContextBuilderCiphertext,
          public ICryptoContextBuilderKeyData,
          public ICryptoContextBuilder
    {
    private:
        CryptoContext *ctx;

    public:
        Impl() { this->ctx = CryptoContext::Factory::CreateCryptoContext(); }

        ICryptoContextBuilderKeyData *noPlaintext()
        {
            return this;
        }

        ICryptoContextBuilderKeyData *noCiphertext()
        {
            return this;
        }

        ICryptoContextBuilder *setKey256(const unsigned char *key) override
        {
            if (!this->ctx->setKey256(key))
            {
                throw InvalidOperation(COULD_NOT_SET_KEY);
            }

            return this;
        }

        ICryptoContextBuilder *setKey(const char *key) override
        {
            if (!this->ctx->setKeyData(key))
            {
                throw InvalidOperation(COULD_NOT_SET_KEY);
            }

            return this;
        }

        ICryptoContextBuilder *setKey(const char *key, char *passphrase) override
        {
            if (!this->ctx->setKeyData(key, passphrase))
            {
                throw InvalidOperation(COULD_NOT_SET_KEY);
            }

            return this;
        }

        ICryptoContextBuilder *readKeyData(const char *path, char *passphrase) override
        {
            if (!this->ctx->readKeyFile(path, passphrase))
            {
                throw InvalidOperation(COULD_NOT_SET_KEY);
            }

            return this;
        }

        ICryptoContextBuilder *readKeyData(const char *path) override
        {
            if (!this->ctx->readKeyFile(path))
            {
                throw InvalidOperation(COULD_NOT_SET_KEY);
            }

            return this;
        }

        ICryptoContextBuilderKeyData *setPlaintext(const unsigned char *data, unsigned int datalen) override
        {
            if (!this->ctx->setPlaintext(data, datalen))
            {
                throw InvalidOperation(COULD_NOT_SET_PLAINTEXT);
            }

            return this;
        }

        ICryptoContextBuilderKeyData *setCiphertext(const unsigned char *data, unsigned int datalen)
        {
            if (!this->ctx->setCiphertext(data, datalen))
            {
                throw InvalidOperation(COULD_NOT_SET_CIPHERTEXT);
            }

            return this;
        }

        ICryptoContextBuilderRsaOperation *useRsa() override
        {
            this->ctx->setCryptoType(AsymmetricCryptography);
            return this;
        }

        ICryptoContextBuilderOperation *useAes() override
        {
            this->ctx->setCryptoType(SymmetricCryptography);
            return this;
        }

        ICryptoContextBuilderPlaintext *useEncryption() override
        {
            this->ctx->setCryptoOp(Encrypt);

            if (!this->ctx->allocateMemory())
            {
                throw InvalidOperation(COULD_NOT_INITIALIZE_CONTEXT);
            }

            return this;
        }

        ICryptoContextBuilderCiphertext *useDecryption() override
        {
            this->ctx->setCryptoOp(Decrypt);

            if (!this->ctx->allocateMemory())
            {
                throw InvalidOperation(COULD_NOT_INITIALIZE_CONTEXT);
            }

            return this;
        }

        ICryptoContextBuilderPlaintext *useSignature() override
        {
            this->ctx->setCryptoOp(Sign);

            if (!this->ctx->allocateMemory())
            {
                throw InvalidOperation(COULD_NOT_INITIALIZE_CONTEXT);
            }

            return this;
        }

        ICryptoContextBuilderCiphertext *useSignatureVerification() override
        {
            this->ctx->setCryptoOp(SignVerify);

            if (!this->ctx->allocateMemory())
            {
                throw InvalidOperation(COULD_NOT_INITIALIZE_CONTEXT);
            }

            return this;
        }

        CryptoContext *build() override
        {
            return this->ctx;
        }
    };

public:
    static ICryptoContextBuilderType *Create()
    {
        return new Impl();
    }
};

#endif