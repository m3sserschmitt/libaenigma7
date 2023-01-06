#ifndef ASYMMETRIC_CIPHER_HH
#define ASYMMETRIC_CIPHER_HH

#include "EvpCipherContext.hh"

class AsymmetricEvpCipherContext : public EvpCipherContext
{
    Bytes encryptedKey;
    int encryptedKeyLength;

    AsymmetricEvpCipherContext(const AsymmetricEvpCipherContext &);
    const AsymmetricEvpCipherContext *operator=(const AsymmetricEvpCipherContext &);

    const EVP_PKEY *getPkey() const { return (EVP_PKEY *)this->getKey()->getKeyMaterial(); }

    EVP_PKEY *getPkey() { return (EVP_PKEY *)this->getKey()->getKeyMaterial(); }

    int getPkeySize() const
    {
        const EVP_PKEY *pkey = this->getPkey();
        return pkey ? EVP_PKEY_size(pkey) : -1;
    }

    void setEncryptedKey(Bytes encryptedKey) { this->encryptedKey = encryptedKey; }

    void setEncryptedKeyLength(Size len) { this->encryptedKeyLength = len; }

    Size getEncryptedKeyLength() const { return this->encryptedKeyLength; }

    Bytes getEncryptedKey() { return this->encryptedKey; }

    const Bytes getEncryptedKey() const { return this->encryptedKey; }

    int *getEncryptedKeyLengthPtr() { return &this->encryptedKeyLength; }

    unsigned char **getEncryptedKeyPtr() { return &this->encryptedKey; }

    void freeEncryptedKey()
    {
        Bytes encryptedKey = this->getEncryptedKey();

        if (encryptedKey)
        {
            memset(encryptedKey, 0, SYMMETRIC_KEY_SIZE);
            delete[] encryptedKey;
            this->setEncryptedKey(nullptr);
            this->setEncryptedKeyLength(0);
        }
    }

    bool allocateEncryptedKey()
    {
        int pkeySize = this->getPkeySize();

        if (pkeySize < 0)
        {
            return false;
        }

        this->freeEncryptedKey();
        this->setEncryptedKey(new Byte[pkeySize + 1]);
        this->setEncryptedKeyLength(0);

        return this->getEncryptedKey() != nullptr;
    }

    bool writeEncryptedKey(ConstBytes encryptedKey)
    {
        Bytes localEncryptedKey = this->getEncryptedKey();

        if (encryptedKey and localEncryptedKey)
        {
            Size encryptedKeySize = this->getPkeySize();
            memcpy(localEncryptedKey, encryptedKey, encryptedKeySize);
            this->setEncryptedKeyLength(encryptedKeySize);
            return true;
        }

        return false;
    }

    bool sealEnvelopeAllocateMemory(const EncrypterData *in)
    {
        return this->allocateCipherContext() and this->allocateEncryptedKey() and this->allocateIV() and this->allocateOutBuffer(in->getDataSize()) and this->allocateTag();
    }

    bool openEnvelopeAllocateMemory(const EncrypterData *in)
    {
        Size outBufferSize = in->getDataSize() - this->getPkeySize() - IV_SIZE - TAG_SIZE;
        return this->allocateCipherContext() and this->allocateEncryptedKey() and this->allocateIV() and this->allocateOutBuffer(outBufferSize) and this->allocateTag();
    }

    Size calculateEnvelopeSize() const
    {
        return this->getEncryptedKeyLength() + IV_SIZE + this->getOutBufferSize() + TAG_SIZE;
    }

    /**
     * @brief Create a Envelope;
     *
     * Envelope structure:
     * N = size of public key (e.g. 2048 bits key length => N = 256 bytes);
     * P = size of plaintext;
     *
     * Encrypted Key: bytes 0..N-1;
     * Initialization Vector: bytes N..N+11 (AES GCM default IV length of 12 bytes);
     * Encrypted buffer: bytes N+12..N+P+11;
     * Tag: bytes N+P+11..N+P+26 (AES GCM tag size of 16 bytes);
     * @return EncrypterResult* Structure containing envelope data and size;
     */
    EncrypterResult *createEnvelope() const;

    ConstBytes readEnvelope(const EncrypterData *in, Size &cipherlen);

    void cleanup() override
    {
        EvpCipherContext::cleanup();
        this->freeEncryptedKey();
    }

    void init()
    {
        this->setEncryptedKey(nullptr);
        this->setEncryptedKeyLength(0);
    }

public:
    AsymmetricEvpCipherContext(Key *key) : EvpCipherContext(key) { this->init(); }

    EncrypterResult *encrypt(const EncrypterData *in) override;

    EncrypterResult *decrypt(const EncrypterData *in) override;

    static EvpContext *create(Key *key) { return new AsymmetricEvpCipherContext(key); }
};

#endif
