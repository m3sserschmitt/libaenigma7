#ifndef EVP_CONTEXT_HH
#define EVP_CONTEXT_HH

#include "Constants.hh"
#include "EncrypterData.hh"
#include "EncrypterResult.hh"
#include "Key.hh"

class EvpContext
{
private:
    Key *key;

    unsigned char *outBuffer;
    int outBufferSize;

protected:
    Key *getKey() { return this->key; }

    [[nodiscard]] int getKeySize() const { return this->key->getSize(); }

    unsigned char *getOutBuffer() { return this->outBuffer; }

    [[nodiscard]] const unsigned char *getOutBuffer() const { return this->outBuffer; }

    void setOutBuffer(unsigned char *outBufferData) { this->outBuffer = outBufferData; }

    void setOutBufferSize(int outBufferLen) { this->outBufferSize = outBufferLen; }

    [[nodiscard]] unsigned int getOutBufferSize() const { return this->outBufferSize; }

    void freeOutBuffer()
    {
        unsigned char *outBufferData = this->getOutBuffer();

        if (outBufferData)
        {
            memset(outBufferData, 0, this->getOutBufferSize());
            delete[] outBufferData;
            this->setOutBuffer(nullptr);
            this->setOutBufferSize(0);
        }
    }

    void allocateOutBuffer(unsigned int len)
    {
        if (not this->getOutBuffer())
        {
            this->setOutBuffer(new unsigned char[len + 1]);
            this->setOutBufferSize(0);
        }
    }

    EncrypterResult *abort()
    {
        this->cleanup();
        return new EncrypterResult(false);
    }

public:
    explicit EvpContext(Key *key)
    {
        this->key = key;
        this->outBuffer = nullptr;
        this->outBufferSize = 0;
    }

    virtual ~EvpContext() { this->freeOutBuffer(); }

    EvpContext(const EvpContext &) = delete;
    const EvpContext &operator=(const EvpContext &) = delete;

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

    virtual void cleanup() { this->freeOutBuffer(); }
};

#endif
