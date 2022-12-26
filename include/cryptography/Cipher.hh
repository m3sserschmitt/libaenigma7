#ifndef CIPHER_HH
#define CIPHER_HH

#include "Constants.hh"
#include "EncrypterData.hh"
#include "EncrypterResult.hh"
#include "RandomDataGenerator.hh"
#include "Key.hh"

#include <openssl/evp.h>

class Cipher
{
    Key *key;

    EVP_CIPHER_CTX *cipherContext;

    Bytes iv;

    Bytes outBuffer;
    int outBufferSize;

    Bytes tag;

    void init(Key *key)
    {
        this->setKey(key);
        this->setCipherContext(nullptr);
        this->setIV(nullptr);
        this->setOutBuffer(nullptr);
        this->setOutBufferSize(0);
        this->setTag(nullptr);
    }

    void setKey(Key *key) { this->key = key; }

    void setCipherContext(EVP_CIPHER_CTX *cipherContext) { this->cipherContext = cipherContext; }

protected:
    const Key *getKey() const { return this->key; }

    EVP_CIPHER_CTX *getCipherContext() { return this->cipherContext; }

    void freeCipherContext()
    {
        EVP_CIPHER_CTX_free(this->getCipherContext());
        this->setCipherContext(nullptr);
    }

    bool allocateCipherContext()
    {
        this->freeCipherContext();
        this->setCipherContext(EVP_CIPHER_CTX_new());

        return this->getCipherContext() != nullptr;
    }

    Bytes getTag() { return this->tag; }

    const Bytes getTag() const { return this->tag; }

    void setTag(Bytes tag) { this->tag = tag; }

    bool writeTag(ConstBytes tag)
    {
        Bytes localTag = this->getTag();
        if (tag and localTag)
        {
            memcpy(localTag, tag, TAG_SIZE);
            return true;
        }

        return false;
    }

    Bytes getOutBuffer() { return this->outBuffer; }

    const Bytes getOutBuffer() const { return this->outBuffer; }

    void setOutBuffer(Bytes outBuffer) { this->outBuffer = outBuffer; }

    void setOutBufferSize(Size outBufferSize) { this->outBufferSize = outBufferSize; }

    Size getOutBufferSize() const { return this->outBufferSize; }

    int *getOutBufferSizePtr() { return &this->outBufferSize; }

    void setIV(Bytes iv) { this->iv = iv; }

    Bytes getIV() { return this->iv; }

    const Bytes getIV() const { return this->iv; }

    bool writeIV(ConstBytes iv)
    {
        Bytes localIV = this->getIV();

        if (localIV and iv)
        {
            memcpy(localIV, iv, IV_SIZE);
            return true;
        }

        return false;
    }

    void freeIV()
    {
        Bytes iv = this->getIV();

        if (iv)
        {
            memset(iv, 0, IV_SIZE);
            delete[] iv;
            this->setIV(nullptr);
        }
    }

    bool allocateIV()
    {
        if (not this->getIV())
        {
            this->setIV(new Byte[IV_SIZE + 1]);
            return this->getIV() != nullptr;
        }

        return true;
    }

    bool generateIV()
    {
        ConstBytes randomData = RandomDataGenerator::generate(IV_SIZE);
        bool ok = this->writeIV(randomData);
        delete[] randomData;

        return ok;
    }

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

    void freeTag()
    {
        Bytes tag = this->getTag();

        if (tag)
        {
            memset(tag, 0, TAG_SIZE);
            delete[] tag;
            this->setTag(nullptr);
        }
    }

    bool allocateTag()
    {
        if (not this->getTag())
        {
            this->setTag(new Byte[TAG_SIZE + 1]);

            return this->getTag() != nullptr;
        }

        return true;
    }

    virtual void cleanup()
    {
        this->freeCipherContext();
        this->freeIV();
        this->freeOutBuffer();
        this->freeTag();
    }

    EncrypterResult *abort()
    {
        this->cleanup();
        return new EncrypterResult(false);
    }

public:
    Cipher(Key *key) { this->init(key); }

    virtual EncrypterResult *encrypt(const EncrypterData *in) = 0;

    virtual EncrypterResult *decrypt(const EncrypterData *in) = 0;
};

#endif