#ifndef EVP_CIPHER_CONTEXT_HH
#define EVP_CIPHER_CONTEXT_HH

#include "EvpContext.hh"

class EvpCipherContext : public EvpContext
{
private:
    void *cipherContext;

    unsigned char * iv;
    unsigned char * tag;

protected:
    void *getCipherContext() { return this->cipherContext; }

    void freeCipherContext();

    void allocateCipherContext();

    unsigned char * getTag() { return this->tag; }

    [[nodiscard]] const unsigned char * getTag() const { return this->tag; }

    bool writeTag(const unsigned char * tagData)
    {
        unsigned char * localTag = this->getTag();
        if (tagData and localTag)
        {
            memcpy(localTag, tagData, TAG_SIZE);
            return true;
        }

        return false;
    }

    unsigned char * getIV() { return this->iv; }

    [[nodiscard]] const unsigned char * getIV() const { return this->iv; }

    bool writeIV(const unsigned char * ivData)
    {
        unsigned char * localIV = this->getIV();

        if (localIV and ivData)
        {
            memcpy(localIV, ivData, IV_SIZE);
            return true;
        }

        return false;
    }

    void freeIV()
    {
        unsigned char * ivData = this->getIV();

        if (ivData)
        {
            memset(ivData, 0, IV_SIZE);
            delete[] ivData;
            this->iv = nullptr;
        }
    }

    void allocateIV()
    {
        if (not this->getIV())
        {
            this->iv = new unsigned char[IV_SIZE + 1];
        }
    }

    bool generateIV();

    void freeTag()
    {
        unsigned char * tagData = this->getTag();

        if (tagData)
        {
            memset(tagData, 0, TAG_SIZE);
            delete[] tagData;
            this->tag = nullptr;
        }
    }

    void allocateTag()
    {
        if (not this->getTag())
        {
            this->tag = new unsigned char[TAG_SIZE + 1];
        }
    }

public:
    explicit EvpCipherContext(Key *key) : EvpContext(key)
    {
        this->cipherContext = nullptr;
        this->iv = nullptr;
        this->tag = nullptr;
    }

    EvpCipherContext(const EvpCipherContext &) = delete;
    const EvpCipherContext& operator=(const EvpCipherContext &) = delete;

    ~EvpCipherContext() override
    {
        this->freeCipherContext();
        this->freeIV();
        this->freeTag();
    }

    void cleanup() override
    {
        EvpContext::cleanup();

        this->freeCipherContext();
        this->freeIV();
        this->freeTag();
    }
};

#endif
