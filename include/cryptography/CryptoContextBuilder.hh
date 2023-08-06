#ifndef CRYPTO_CONTEXT_BUILDER_HH
#define CRYPTO_CONTEXT_BUILDER_HH

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
        Impl() { this->ctx = CryptoContext::CreateCryptoContext(); }

        ICryptoContextBuilderKeyData *noPlaintext()
        {
            return this;
        }

        ICryptoContextBuilderKeyData *noCiphertext()
        {
            return this;
        }

        ICryptoContextBuilder *setKey256(ConstBytes key) override
        {
            this->ctx->setKey256(key);
            return this;
        }

        ICryptoContextBuilder *setKey(ConstPlaintext key) override
        {
            this->ctx->setKeyData(key);
            return this;
        }

        ICryptoContextBuilder *setKey(ConstPlaintext key, Plaintext passphrase) override
        {
            this->ctx->setKeyData(key, passphrase);
            return this;
        }

        ICryptoContextBuilder *readKeyData(ConstPlaintext path, Plaintext passphrase) override
        {
            this->ctx->readKeyFile(path, passphrase);
            return this;
        }

        ICryptoContextBuilder *readKeyData(ConstPlaintext path) override
        {
            this->ctx->readKeyFile(path);
            return this;
        }

        ICryptoContextBuilderKeyData *setPlaintext(ConstBytes data, Size datalen) override
        {
            this->ctx->setPlaintext(data, datalen);
            return this;
        }

        ICryptoContextBuilderKeyData *setCiphertext(ConstBytes data, Size datalen)
        {
            this->ctx->setCiphertext(data, datalen);
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
            this->ctx->setup();
            return this;
        }

        ICryptoContextBuilderCiphertext *useDecryption() override
        {
            this->ctx->setCryptoOp(Decrypt);
            this->ctx->setup();
            return this;
        }

        ICryptoContextBuilderPlaintext *useSignature() override
        {
            this->ctx->setCryptoOp(Sign);
            this->ctx->setup();
            return this;
        }

        ICryptoContextBuilderCiphertext *useSignatureVerification() override
        {
            this->ctx->setCryptoOp(SignVerify);
            this->ctx->setup();
            return this;
        }

        ICryptoContext *build() override
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