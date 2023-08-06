#ifndef EVP_MD_CONTEXT_HH
#define EVP_MD_CONTEXT_HH

#include "EvpContext.hh"

class EvpMdContext : public EvpContext
{
    EVP_MD_CTX *mdContext;

    Bytes inSig;
    Size inSiglen;

    void init() 
    { 
        this->setMdContext(nullptr); 
        this->setInSig(nullptr);
        this->setInSiglen(0);
    }

    void setMdContext(EVP_MD_CTX *mdContext) { this->mdContext = mdContext; }

    const EVP_MD_CTX *getMdContext() const { return this->mdContext; }

    EVP_MD_CTX *getMdContext() { return this->mdContext; }

    void setInSig(Bytes inSig) { this->inSig = inSig; }

    Bytes getInSig() { return this->inSig; }

    const Bytes getInSig() const { return this->inSig; }

    Size getInSiglen() const { return this->inSiglen; }

    void setInSiglen(Size inSiglen) { this->inSiglen = inSiglen; }

    bool notNullInSig() const { return this->getInSig() != nullptr; }

    void freeInSig()
    {
        Bytes inSig = this->getInSig();

        if (inSig)
        {
            memset(inSig, 0, this->getInSiglen());
            delete[] this->getInSig();
            this->setInSig(nullptr);
        }
    }

    bool allocateInSig(Size len)
    {
        this->freeInSig();
        this->setInSig(new Byte[len + 1]);

        return this->notNullInSig();
    }

    bool writeInSig(ConstBytes inSig, Size len)
    {
        Bytes localInSig = this->getInSig();

        if (inSig and localInSig)
        {
            memcpy(localInSig, inSig, len);
            this->setInSiglen(len);
            return true;
        }

        return false;
    }

    void freeMdContext()
    {
        EVP_MD_CTX_free(this->getMdContext());
        this->setMdContext(nullptr);
    }

    bool allocateMdContext()
    {
        this->freeMdContext();
        this->setMdContext(EVP_MD_CTX_new());

        return this->getMdContext() != nullptr;
    }

    EncrypterResult *createSignedData(const EncrypterData *in) const;

    ConstBytes readSignedData(const EncrypterData *in, Size &signlen);

    bool notNullMdContext() const { return this->getMdContext() != nullptr; }

    void cleanup() override
    {
        EvpContext::cleanup();

        this->freeMdContext();
        this->freeInSig();
    }

public:
    EvpMdContext(Key *key) : EvpContext(key) { this->init(); }

    ~EvpMdContext()
    {
        this->freeInSig();
        this->freeMdContext();
    }

    EncrypterResult *encrypt(const EncrypterData *in) override;

    EncrypterResult *decrypt(const EncrypterData *in) override;

    static EvpContext *create(Key *key) { return new EvpMdContext(key); }
};

#endif
