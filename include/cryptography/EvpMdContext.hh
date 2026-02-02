#ifndef EVP_MD_CONTEXT_HH
#define EVP_MD_CONTEXT_HH

#include "EvpContext.hh"

class EvpMdContext : public EvpContext
{
private:
    void *mdContext;

    unsigned char *inSig;
    unsigned int inSigLen;

    void freeInSig()
    {
        if (this->inSig)
        {
            memset(this->inSig, 0, this->inSigLen);
            delete[] this->inSig;
            this->inSig = nullptr;
        }
    }

    void allocateInSig(unsigned int len)
    {
        this->freeInSig();
        this->inSig = new unsigned char[len + 1];
    }

    bool writeInSig(const unsigned char *inSigData, unsigned int len)
    {
        if (inSigData and this->inSig)
        {
            memcpy(this->inSig, inSigData, len);
            this->inSigLen = len;
            return true;
        }

        return false;
    }

    void freeMdContext();

    bool allocateMdContext();

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
     * @param dataSize if successful it contains the data size
     * @return const unsigned char * pointer to data
     */
    const unsigned char *readSignedData(const EncrypterData *in, int &dataSize);

public:
    explicit EvpMdContext(Key *key) : EvpContext(key)
    {
        this->mdContext = nullptr;
        this->inSig = nullptr;
        this->inSigLen = 0;
    }

    ~EvpMdContext() override
    {
        this->freeInSig();
        this->freeMdContext();
    }

    EvpMdContext(const EvpMdContext &) = delete;
    const EvpMdContext &operator=(const EvpMdContext &) = delete;

    EncrypterResult *encrypt(const EncrypterData *in) override;

    EncrypterResult *decrypt(const EncrypterData *in) override;

    void cleanup() override
    {
        EvpContext::cleanup();

        this->freeMdContext();
        this->freeInSig();
    }
};

#endif
