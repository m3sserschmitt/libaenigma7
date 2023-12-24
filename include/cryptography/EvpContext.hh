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

protected:

    Key *getKey() { return this->key; }

    int getKeySize() const { return this->key->getSize(); }

    Bytes getOutBuffer() { return this->outBuffer; }

    const Bytes getOutBuffer() const { return this->outBuffer; }

    void setOutBuffer(Bytes outBuffer) { this->outBuffer = outBuffer; }

    void setOutBufferSize(Size outBufferSize) { this->outBufferSize = outBufferSize; }

    Size getOutBufferSize() const { return this->outBufferSize; }

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

    EncrypterResult *abort()
    {
        this->cleanup();
        return new EncrypterResult(false);
    }

public:

    EvpContext(Key *key)
    {
        this->key = key;
        this->setOutBuffer(nullptr);
        this->setOutBufferSize(0);
    }

    virtual ~EvpContext() { this->freeOutBuffer(); }

    /**
     * @brief Transform plaintext provided as input into ciphertext.
     * 
     * @param in Input data - plaintext
     * @return EncrypterResult* Output data - ciphertext
     */
    virtual EncrypterResult *encrypt(const EncrypterData *in) = 0;

    /**
     * @brief Transform ciphertext provided as input into plaintext
     * 
     * @param in Input data - ciphertext
     * @return EncrypterResult* Output data - plaintext
     */
    virtual EncrypterResult *decrypt(const EncrypterData *in) = 0;

    virtual void cleanup()
    {
        this->freeOutBuffer();
    }
};

#endif
