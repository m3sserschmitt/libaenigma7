#ifndef EVP_CONTEXT_HH
#define EVP_CONTEXT_HH

#include "Constants.hh"
#include "EncrypterData.hh"
#include "EncrypterResult.hh"
#include "RandomDataGenerator.hh"
#include "Key.hh"

#include <openssl/evp.h>

class EvpContext
{
    Key *key;

    Bytes outBuffer;
    int outBufferSize;

    void init(Key *key)
    {
        this->setKey(key);

        this->setOutBuffer(nullptr);
        this->setOutBufferSize(0);
    }

    void setKey(Key *key) { this->key = key; }

protected:
    const Key *getKey() const { return this->key; }

    const EVP_PKEY *getPkey() const { return (EVP_PKEY *)this->getKey()->getKeyData(); }

    EVP_PKEY *getPkey() { return (EVP_PKEY *)this->getKey()->getKeyData(); }

    int getPkeySize() const
    {
        const EVP_PKEY *pkey = this->getPkey();
        return pkey ? EVP_PKEY_size(pkey) : -1;
    }

    Bytes getOutBuffer() { return this->outBuffer; }

    const Bytes getOutBuffer() const { return this->outBuffer; }

    void setOutBuffer(Bytes outBuffer) { this->outBuffer = outBuffer; }

    void setOutBufferSize(Size outBufferSize) { this->outBufferSize = outBufferSize; }

    Size getOutBufferSize() const { return this->outBufferSize; }

    int *getOutBufferSizePtr() { return &this->outBufferSize; }

    void freeOutBuffer()
    {
        Bytes outBuffer = this->getOutBuffer();

        if (outBuffer)
        {
            memset(outBuffer, 0, this->getOutBufferSize());
            delete[] outBuffer;
            this->setOutBuffer(nullptr);
            this->setOutBufferSize(0);
        }
    }

    bool allocateOutBuffer(Size len)
    {
        if (not this->getOutBuffer())
        {
            this->setOutBuffer(new Byte[len + 1]);
            this->setOutBufferSize(0);

            return this->getOutBuffer() != nullptr;
        }

        return true;
    }

    virtual void cleanup()
    {
        this->freeOutBuffer();
    }

    EncrypterResult *abort()
    {
        this->cleanup();
        return new EncrypterResult(false);
    }

public:
    EvpContext(Key *key) { this->init(key); }

    virtual ~EvpContext() { this->freeOutBuffer(); }

    virtual EncrypterResult *encrypt(const EncrypterData *in) = 0;

    virtual EncrypterResult *decrypt(const EncrypterData *in) = 0;
};

#endif