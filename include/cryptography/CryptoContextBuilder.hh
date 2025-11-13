#ifndef CRYPTO_CONTEXT_BUILDER_HH
#define CRYPTO_CONTEXT_BUILDER_HH

#include <exception>

#include "contracts/ICryptoContextBuilderType.hh"
#include "CryptoContext.hh"
#include "PublicKey.hh"
#include "PrivateKey.hh"
#include "SymmetricKey.hh"
#include "SymmetricEvpCipherContext.hh"
#include "EncryptionMachine.hh"
#include "DecryptionMachine.hh"
#include "AsymmetricEvpCipherContext.hh"
#include "EvpMdContext.hh"

class CryptoContextBuilder
{
private:
    class Impl
        : public ICryptoContextBuilderType,
          public ICryptoContextBuilderRsaOperation,
          public ICryptoContextBuilderAesOperation,
          public ICryptoContextBuilderKeyData,
          public ICryptoContextBuilder
    {
    private:
        bool error;
        Key *key;
        CryptoContext *ctx;

    public:
        Impl()
        {
            this->ctx = nullptr;
            this->key = nullptr;
            error = false;
        }

        ~Impl() override
        {
            delete this->ctx;
            this->ctx = nullptr;
        }

        ICryptoContextBuilder *setKey(const unsigned char *keyData) override
        {
            error &= this->key->setKeyData(keyData, SYMMETRIC_KEY_SIZE, nullptr);
            return this;
        }

        ICryptoContextBuilder *setKey(const char *keyData) override
        {
            error &= this->key->setKeyData((const unsigned char *)keyData, strlen(keyData), nullptr);
            return this;
        }

        ICryptoContextBuilder *setKey(const char *keyData, const char *passphrase) override
        {
            error &= this->key->setKeyData((const unsigned char *)keyData, strlen(keyData), passphrase);
            return this;
        }

        ICryptoContextBuilder *readKeyData(const char *path, const char *passphrase) override
        {
            error &= this->key->readKeyFile(path, passphrase);
            return this;
        }

        ICryptoContextBuilder *readKeyData(const char *path) override
        {
            error &= this->key->readKeyFile(path, nullptr);
            return this;
        }

        ICryptoContextBuilderRsaOperation *useRsa() override
        {
            this->key = nullptr;
            this->ctx = nullptr;
            error = false;
            return this;
        }

        ICryptoContextBuilderAesOperation *useAes() override
        {
            this->key = nullptr;
            this->ctx = nullptr;
            error = false;
            return this;
        }

        ICryptoContextBuilderKeyData *useEncryption() override
        {
            if(error)
            {
                return this;
            }
            this->key = new SymmetricKey();
            EvpContext *cipher = new SymmetricEvpCipherContext(this->key);
            this->ctx = new CryptoContext(this->key, cipher, new EncryptionMachine(cipher));
            return this;
        }

        ICryptoContextBuilderKeyData *useDecryption() override
        {
            if(error)
            {
                return this;
            }
            this->key = new SymmetricKey();
            EvpContext *cipher = new SymmetricEvpCipherContext(this->key);
            this->ctx = new CryptoContext(this->key, cipher, new DecryptionMachine(cipher));
            return this;
        }

        ICryptoContextBuilderKeyData *useSignature() override
        {
            if(error)
            {
                return this;
            }
            this->key = new PrivateKey();
            EvpContext *cipher = new EvpMdContext(this->key);
            this->ctx = new CryptoContext(this->key, cipher, new EncryptionMachine(cipher));
            return this;
        }

        ICryptoContextBuilderKeyData *useSignatureVerification() override
        {
            if(error)
            {
                return this;
            }
            this->key = new PublicKey();
            EvpContext *cipher = new EvpMdContext(this->key);
            this->ctx = new CryptoContext(this->key, cipher, new DecryptionMachine(cipher));
            return this;
        }

        ICryptoContextBuilderKeyData *useSealing() override
        {
            if(error)
            {
                return this;
            }
            this->key = new PublicKey();
            EvpContext *cipher = new AsymmetricEvpCipherContext(this->key);
            this->ctx = new CryptoContext(this->key, cipher, new EncryptionMachine(cipher));
            return this;
        }

        ICryptoContextBuilderKeyData *useUnsealing() override
        {
            if(error)
            {
                return this;
            }
            this->key = new PrivateKey();
            EvpContext *cipher = new AsymmetricEvpCipherContext(this->key);
            this->ctx = new CryptoContext(this->key, cipher, new DecryptionMachine(cipher));
            return this;
        }

        CryptoContext *build() override
        {
            CryptoContext *tempCtx = this->ctx;
            this->ctx = nullptr;
            return error ? nullptr : tempCtx;
        }
    };
public:
    CryptoContextBuilder(const CryptoContextBuilder &) = delete;
    const CryptoContextBuilder &operator=(const CryptoContextBuilder &) = delete;

    static ICryptoContextBuilderType *Create() { return new Impl(); }
};

#endif
