#ifndef EVP_CIPHER_CONTEXT_HH
#define EVP_CIPHER_CONTEXT_HH

#include "EvpContext.hh"

class EvpCipherContext : public EvpContext
{
    EVP_CIPHER_CTX *cipherContext;

    Bytes iv;
    Bytes tag;

protected:
    EVP_CIPHER_CTX *getCipherContext() { return this->cipherContext; }

    void freeCipherContext()
    {
        EVP_CIPHER_CTX_free(this->getCipherContext());
        this->cipherContext = nullptr;
    }

    bool allocateCipherContext()
    {
        this->freeCipherContext();
        this->cipherContext = EVP_CIPHER_CTX_new();

        return this->getCipherContext() != nullptr;
    }

    Bytes getTag() { return this->tag; }

    const Bytes getTag() const { return this->tag; }

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
            this->iv = nullptr;
        }
    }

    bool allocateIV()
    {
        if (not this->getIV())
        {
            this->iv = new Byte[IV_SIZE + 1];
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

    void freeTag()
    {
        Bytes tag = this->getTag();

        if (tag)
        {
            memset(tag, 0, TAG_SIZE);
            delete[] tag;
            this->tag = nullptr;
        }
    }

    bool allocateTag()
    {
        if (not this->getTag())
        {
            this->tag = new Byte[TAG_SIZE + 1];

            return this->getTag() != nullptr;
        }

        return true;
    }

public:

    EvpCipherContext(Key *key) : EvpContext(key)
    {
        this->cipherContext = nullptr;
        this->iv = nullptr;
        this->tag = nullptr;
    }

    ~EvpCipherContext()
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
