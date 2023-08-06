#ifndef EVP_CIPHER_CONTEXT_HH
#define EVP_CIPHER_CONTEXT_HH

#include "EvpContext.hh"

class EvpCipherContext : public EvpContext
{
    EVP_CIPHER_CTX *cipherContext;

    Bytes iv;
    Bytes tag;

    void setCipherContext(EVP_CIPHER_CTX *cipherContext) { this->cipherContext = cipherContext; }

    void init()
    {
        this->setCipherContext(nullptr);
        this->setIV(nullptr);
        this->setTag(nullptr);
    }

protected:
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

    void cleanup() override
    {
        EvpContext::cleanup();

        this->freeCipherContext();
        this->freeIV();
        this->freeTag();
    }

public:
    EvpCipherContext(Key *key) : EvpContext(key) { this->init(); }

    ~EvpCipherContext()
    {
        this->freeCipherContext();
        this->freeIV();
        this->freeTag();
    }
};

#endif
