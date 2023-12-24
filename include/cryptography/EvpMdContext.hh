#ifndef EVP_MD_CONTEXT_HH
#define EVP_MD_CONTEXT_HH

#include "EvpContext.hh"

class EvpMdContext : public EvpContext
{
    EVP_MD_CTX *mdContext;

    Bytes inSig;
    Size inSiglen;

    bool notNullInSig() const { return this->inSig != nullptr; }

    void freeInSig()
    {
        if (this->inSig)
        {
            memset(this->inSig, 0, this->inSiglen);
            delete[] this->inSig;
            this->inSig = nullptr;
        }
    }

    bool allocateInSig(Size len)
    {
        this->freeInSig();
        this->inSig = new Byte[len + 1];

        return this->notNullInSig();
    }

    bool writeInSig(ConstBytes inSig, Size len)
    {
        if (inSig and this->inSig)
        {
            memcpy(this->inSig, inSig, len);
            this->inSiglen = len;
            return true;
        }

        return false;
    }

    void freeMdContext()
    {
        EVP_MD_CTX_free(this->mdContext);
        this->mdContext = nullptr;
    }

    bool allocateMdContext()
    {
        this->freeMdContext();
        this->mdContext = EVP_MD_CTX_new();

        return this->mdContext != nullptr;
    }

    /**
     * @brief Create a signature
     *
     * Signature structure
     * 1. Data
     * 2. Digest (signature)
     *
     * @param in Structure containing data to be signed and its size
     * @return EncrypterResult* structure containing byte array with the output and its size
     */
    EncrypterResult *createSignedData(const EncrypterData *in) const;

    /**
     * @brief Read a byte array resulted from createSignedData and initializes internal structures
     *
     * @param in structure containing data do be verified and its size
     * @param datasize if successful it contains the data size
     * @return ConstBytes pointer to data
     */
    ConstBytes readSignedData(const EncrypterData *in, Size &datasize);

    bool notNullMdContext() const { return this->mdContext != nullptr; }

public:
    EvpMdContext(Key *key) : EvpContext(key)
    {
        this->mdContext = nullptr;
        this->inSig = nullptr;
        this->inSiglen = 0;
    }

    ~EvpMdContext()
    {
        this->freeInSig();
        this->freeMdContext();
    }

    EncrypterResult *encrypt(const EncrypterData *in) override;

    EncrypterResult *decrypt(const EncrypterData *in) override;

    void cleanup() override
    {
        EvpContext::cleanup();

        this->freeMdContext();
        this->freeInSig();
    }

    class Factory
    {
    public:
        /**
         * @brief Create new EvpMdContext to be used for signing or verification
         *
         * @param key AsymmetricKey object initialized accordingly
         * @return EvpContext* Newly created EvpMdContext
         */
        static EvpMdContext *create(Key *key) { return new EvpMdContext(key); }
    };
};

#endif
